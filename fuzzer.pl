:- initialization(main).

lib(443, 'libc.musl-aarch64.so.1').
lib(32, 'libcgraph.so.6').
lib(29, 'libstdc++.so.6').
lib(29, 'libintl.so.8').
lib(20, 'libgvc.so.6').
lib(16, 'libglib-2.0.so.0').
lib(16, 'libgettextlib-0.24.1.so').
lib(15, 'libgettextsrc-0.24.1.so').
lib(15, 'libgcc_s.so.1').
lib(14, 'libz.so.1').
lib(14, 'libgobject-2.0.so.0').
lib(14, 'libbfd-2.45.1.so').
lib(12, 'libtextstyle.so.0').
lib(11, 'libicuuc.so.76').
lib(11, 'libexpat.so.1').
lib(10, 'libsndfile.so.1').
lib(10, 'libicutu.so.76').
lib(10, 'libfontconfig.so.1').
lib(10, 'libSPIRV-Tools.so').
lib(9, 'liblzma.so.5').
lib(8, 'libzstd.so.1').
lib(8, 'libwinpr3.so.3').
lib(8, 'libgio-2.0.so.0').
lib(8, 'libcdt.so.5').
lib(7, 'libfreerdp3.so.3').
lib(5, 'libssl.so.3').
lib(5, 'libpipewire-0.3.so.0').
lib(5, 'libpcre2-8.so.0').
lib(5, 'libcrypto.so.3').
lib(4, 'libxml2.so.2').
lib(4, 'libfreerdp-client3.so.3').
lib(4, 'libX11.so.6').
lib(3, 'libuv.so.1').
lib(3, 'librhash.so.1').
lib(3, 'libreadline.so.8').
lib(3, 'libpython3.12.so.1.0').
lib(3, 'libpkgconf.so.7').
lib(3, 'libpangocairo-1.0.so.0').
lib(3, 'libpango-1.0.so.0').
lib(3, 'libjansson.so.4').
lib(3, 'libicui18n.so.76').
lib(3, 'libgirepository-2.0.so.0').
lib(3, 'libctf.so.0').
lib(3, 'libarchive.so.13').
lib(3, 'libSPIRV-Tools-opt.so').

main :-
    setup_csv,
    format('Starting True Dynamic Fuzzing Campaign on Alpine~n', []),
    forall(lib(Freq, LibName), fuzz_library(Freq, LibName)),
    format('Fuzzing campaign complete. Results saved to fuzz_results.csv~n', []),
    halt.

setup_csv :-
    open('fuzz_results.csv', write, Stream),
    write(Stream, 'Frequency,SharedLibrary,TestsRun,Successes,Failures,FailureMode\n'),
    close(Stream).

fuzz_library(Freq, LibName) :-
    sformat(LibPath, '/lib/~w', [LibName]),
    sformat(LibUsrPath, '/usr/lib/~w', [LibName]),
    (   exists_file(LibPath) -> Target = LibPath
    ;   exists_file(LibUsrPath) -> Target = LibUsrPath
    ;   Target = missing
    ),
    run_fuzz_loop(Target, Freq, 0, 0, 0, 'None', Runs, Successes, Failures, FinalMode),
    append_csv(Freq, LibName, Runs, Successes, Failures, FinalMode).

run_fuzz_loop(missing, Freq, _, _, _, _, Freq, 0, Freq, 'LibraryNotFound').
run_fuzz_loop(Target, Freq, AccRuns, AccSucc, AccFail, AccMode, Runs, Succ, Fail, Mode) :-
    Target \= missing,
    ( AccRuns < Freq ->
        invoke_harness(Target, Status),
        ( Status == 'None' ->
            NewSucc is AccSucc + 1,
            NewFail is AccFail,
            NewMode = AccMode
        ;   NewSucc is AccSucc,
            NewFail is AccFail + 1,
            NewMode = Status
        ),
        NewRuns is AccRuns + 1,
        run_fuzz_loop(Target, Freq, NewRuns, NewSucc, NewFail, NewMode, Runs, Succ, Fail, Mode)
    ;   Runs = AccRuns,
        Succ = AccSucc,
        Fail = AccFail,
        Mode = AccMode
    ).

invoke_harness(Target, Status) :-
    sformat(Cmd, './fuzz_runner %w', [Target]),
    setup_call_cleanup(
        open(pipe(Cmd, read), Stream),
        read_stream_to_status(Stream, Status),
        close(Stream)
    ).

read_stream_to_status(Stream, Status) :-
    read_line_to_string(Stream, Line),
    (   string(Line), sub_string(Line, 0, _, _, "FailMode: ") ->
        sub_string(Line, 10, _, 0, Status)
    ;   Status = 'UnknownError'
    ).

append_csv(Freq, LibName, Runs, Successes, Failures, Mode) :-
    open('fuzz_results.csv', append, Stream),
    format(Stream, '~w,~w,~w,~w,~w,~w~n', [Freq, LibName, Runs, Successes, Failures, Mode]),
    close(Stream).
