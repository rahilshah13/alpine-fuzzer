# Alpine Shared Library Fuzzer

* `docker build -t alpine-fuzzer .`
* `docker run --rm -v $(pwd):/app alpine-fuzzer`.
* `fuzz_results.csv` tracks `Frequency,SharedLibrary,TestsRun,Successes,Failures,FailureMode`.
