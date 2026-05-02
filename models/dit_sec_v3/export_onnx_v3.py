import torch
import onnx
from onnx import helper, TensorProto
import numpy as np
import argparse
from pathlib import Path
from typing import Dict, Optional

from dit_sec_model import DITSecModel


def export_to_onnx(
    input_path: str,
    output_path: str,
    quantize: str = "fp32",
    opset_version: int = 14
) -> None:
    """
    Export DIT-Sec model to ONNX format.
    
    Args:
        input_path: Path to PyTorch model checkpoint
        output_path: Output ONNX path
        quantize: Quantization type (fp32, fp16, int8)
        opset_version: ONNX opset version
    """
    print(f"Loading model from {input_path}...")
    
    checkpoint = torch.load(input_path, map_location="cpu")
    
    model = DITSecModel()
    
    if "model_state_dict" in checkpoint:
        model.load_state_dict(checkpoint["model_state_dict"])
    
    model.eval()
    
    print("Creating sample inputs for ONNX export...")
    
    old_spec_sample = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "spec": {
            "replicas": 3,
            "template": {
                "spec": {
                    "containers": [{
                        "name": "app",
                        "image": "nginx:latest",
                        "resources": {
                            "limits": {"cpu": "500m", "memory": "512Mi"},
                            "requests": {"cpu": "250m", "memory": "256Mi"}
                        }
                    }]
                }
            }
        }
    }
    
    new_spec_sample = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "spec": {
            "replicas": 3,
            "template": {
                "spec": {
                    "containers": [{
                        "name": "app",
                        "image": "nginx:latest",
                        "resources": {
                            "limits": {"cpu": "50m", "memory": "512Mi"},
                            "requests": {"cpu": "250m", "memory": "256Mi"}
                        }
                    }]
                }
            }
        }
    }
    
    metrics_sample = torch.randn(1, 60, 15)
    entropy_sample = torch.randn(1, 20)
    
    print("Exporting to ONNX...")
    
    try:
        with torch.no_grad():
            torch.onnx.export(
                model,
                args=(
                    old_spec_sample,
                    new_spec_sample,
                    metrics_sample,
                    None,
                    entropy_sample
                ),
                f=output_path,
                export_params=True,
                opset_version=opset_version,
                do_constant_folding=True,
                input_names=[
                    "old_spec",
                    "new_spec",
                    "metrics",
                    "syscalls",
                    "entropy_series"
                ],
                output_names=[
                    "risk_score",
                    "label",
                    "probabilities"
                ],
                dynamic_axes={
                    "metrics": {0: "batch_size", 1: "num_steps"},
                    "entropy_series": {0: "batch_size"},
                    "risk_score": {0: "batch_size"},
                    "probabilities": {0: "batch_size"}
                }
            )
    except Exception as e:
        print(f"Export error: {e}")
        print("Attempting simplified export...")
        
        try:
            onnx_model = create_onnx_model_simple(
                input_path.replace(".pt", "_simple.onnx")
            )
        except Exception as e2:
            print(f"Simple export also failed: {e2}")
            return
    
    print(f"Model exported to {output_path}")
    
    if quantize == "fp16":
        try:
            from onnxruntime.quantization import quantize_fp16
            quantize_fp16(output_path, output_path.replace(".onnx", "_fp16.onnx"))
            print(f"FP16 model saved to {output_path.replace('.onnx', '_fp16.onnx')}")
        except ImportError:
            print("onnxruntime not available, skipping FP16 quantization")
    
    elif quantize == "int8":
        print("INT8 quantization requires onnxruntime with QDQ operators")
        print("Skipping for now - use fp16 or fp32")
    
    validate_onnx(output_path)


def create_onnx_model_simple(output_path: str) -> None:
    """
    Create a simplified ONNX model manually.
    Used as fallback if PyTorch export fails.
    """
    input_old = helper.make_tensor_value_info(
        'old_spec', TensorProto.FLOAT, [1, 128]
    )
    input_new = helper.make_tensor_value_info(
        'new_spec', TensorProto.FLOAT, [1, 128]
    )
    input_metrics = helper.make_tensor_value_info(
        'metrics', TensorProto.FLOAT, [1, 60, 15]
    )
    input_entropy = helper.make_tensor_value_info(
        'entropy_series', TensorProto.FLOAT, [1, 20]
    )
    
    output_risk = helper.make_tensor_value_info(
        'risk_score', TensorProto.FLOAT, [1]
    )
    output_label = helper.make_tensor_value_info(
        'label', TensorProto.INT64, [1]
    )
    output_probs = helper.make_tensor_value_info(
        'probabilities', TensorProto.FLOAT, [1, 5]
    )
    
    concat = helper.make_node(
        'Concat',
        inputs=['old_spec', 'new_spec'],
        outputs=['concated'],
        axis=1
    )
    
    gemm = helper.make_node(
        'Gemm',
        inputs=['concated'],
        outputs=['risk_score'],
        alpha=0.5,
        beta=0.0,
        transB=1
    )
    
    graph = helper.make_graph(
        [concat, gemm],
        'dit_sec_simple',
        [input_old, input_new, input_metrics, input_entropy],
        [output_risk, output_label, output_probs]
    )
    
    model = helper.make_model(graph, producer_name='kubeheal')
    model.opset_import[0].version = 14
    
    onnx.save(model, output_path)
    print(f"Simple ONNX model saved to {output_path}")


def validate_onnx(model_path: str) -> bool:
    """
    Validate ONNX model can be loaded and produces reasonable output.
    """
    print(f"Validating ONNX model: {model_path}")
    
    try:
        model = onnx.load(model_path)
        onnx.checker.check_model(model)
        print("  ✓ ONNX model is valid")
        
        import onnxruntime as ort
        
        sess = ort.InferenceSession(
            model_path,
            providers=["CPUExecutionProvider"]
        )
        
        inputs = {
            "metrics": np.random.randn(1, 60, 15).astype(np.float32),
            "entropy_series": np.random.randn(1, 20).astype(np.float32)
        }
        
        outputs = sess.run(None, inputs)
        
        risk_score = outputs[0]
        probs = outputs[2]
        
        print(f"  ✓ Risk score: {risk_score[0][0]:.3f}")
        print(f"  ✓ Probabilities: {probs[0]}")
        
        return True
    
    except Exception as e:
        print(f"  ✗ Validation failed: {e}")
        return False


def benchmark_onnx(
    model_path: str,
    num_iterations: int = 100
) -> Dict[str, float]:
    """
    Benchmark ONNX inference latency.
    Goal: <50ms per inference.
    """
    import onnxruntime as ort
    
    sess = ort.InferenceSession(
        model_path,
        providers=["CPUExecutionProvider"]
    )
    
    inputs = {
        "metrics": np.random.randn(1, 60, 15).astype(np.float32),
        "entropy_series": np.random.randn(1, 20).astype(np.float32)
    }
    
    import time
    
    warmup = 10
    for _ in range(warmup):
        _ = sess.run(None, inputs)
    
    latencies = []
    for _ in range(num_iterations):
        start = time.perf_counter()
        _ = sess.run(None, inputs)
        end = time.perf_counter()
        latencies.append((end - start) * 1000)
    
    latencies = np.array(latencies)
    
    return {
        "mean_ms": np.mean(latencies),
        "p50_ms": np.percentile(latencies, 50),
        "p95_ms": np.percentile(latencies, 95),
        "p99_ms": np.percentile(latencies, 99),
        "min_ms": np.min(latencies),
        "max_ms": np.max(latencies)
    }


def main():
    parser = argparse.ArgumentParser(description="Export DIT-Sec to ONNX")
    parser.add_argument("--input", type=str, required=True, help="Input PyTorch model path")
    parser.add_argument("--output", type=str, required=True, help="Output ONNX path")
    parser.add_argument("--quantize", type=str, default="fp32", choices=["fp32", "fp16", "int8"])
    parser.add_argument("--opset", type=int, default=14, help="ONNX opset version")
    
    args = parser.parse_args()
    
    export_to_onnx(
        input_path=args.input,
        output_path=args.output,
        quantize=args.quantize,
        opset_version=args.opset
    )
    
    if Path(args.output).exists():
        benchmark = benchmark_onnx(args.output, num_iterations=100)
        print(f"\nBenchmark results:")
        print(f"  Mean: {benchmark['mean_ms']:.2f}ms")
        print(f"  P50: {benchmark['p50_ms']:.2f}ms")
        print(f"  P95: {benchmark['p95_ms']:.2f}ms")
        print(f"  P99: {benchmark['p99_ms']:.2f}ms")
        
        if benchmark['p95_ms'] < 50:
            print(f"\n✓ Target met: <50ms at P95")
        else:
            print(f"\n✗ Target missed: {benchmark['p95_ms']:.2f}ms > 50ms")


if __name__ == "__main__":
    main()