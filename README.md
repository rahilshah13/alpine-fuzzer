# Alpine Shared Library Fuzzer

* **Container Execution**: Build the image using `docker build -t alpine-fuzzer .` and run it with volume mounting via `docker run --rm -v $(pwd):/app alpine-fuzzer`.
* **Output**: `fuzz_results.csv` tracks `Frequency,SharedLibrary,TestsRun,Successes,Failures,FailureMode`.
