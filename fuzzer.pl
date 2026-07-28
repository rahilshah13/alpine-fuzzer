:- initialization(main).
:- use_module(library(system)).

% Library list without frequencies
lib('libc.musl-aarch64.so.1').
lib('libcgraph.so.6').
lib('libstdc++.so.6').
lib('libintl.so.8').
lib('libgvc.so.6').
lib('libglib-2.0.so.0').
lib('libgettextlib-0.24.1.so').
lib('libgettextsrc-0.24.1.so').
lib('libgcc_s.so.1').
lib('libz.so.1').
lib('libgobject-2.0.so.0').
lib('libbfd-2.45.1.so').
lib('libtextstyle.so.0').
lib('libicuuc.so.76').
lib('libexpat.so.1').
lib('libsndfile.so.1').
lib('libicutu.so.76').
lib('libfontconfig.so.1').
lib('libSPIRV-Tools.so').
lib('liblzma.so.5').
lib('libzstd.so.1').
lib('libwinpr3.so.3').
lib('libgio-2.0.so.0').
lib('libcdt.so.5').
lib('libfreerdp3.so.3').
lib('libssl.so.3').
lib('libpipewire-0.3.so.0').
lib('libpcre2-8.so.0').
lib('libcrypto.so.3').
lib('libxml2.so.2').
lib('libfreerdp-client3.so.3').
lib('libX11.so.6').
lib('libuv.so.1').
lib('librhash.so.1').
lib('libreadline.so.8').
lib('libpython3.12.so.1.0').
lib('libpkgconf.so.7').
lib('libpangocairo-1.0.so.0').
lib('libpango-1.0.so.0').
lib('libjansson.so.4').
lib('libicui18n.so.76').
lib('libgirepository-2.0.so.0').
lib('libctf.so.0').
lib('libarchive.so.13').
lib('libSPIRV-Tools-opt.so').

sformat(String, Format, Args) :-
    ( is_list(Args) -> format(string(String), Format, Args)
    ; format(string(String), Format, [Args])
    ).

main :-
    setup_report,
    format('Starting Dynamic Fuzzing Campaign on Alpine~n', []),
    forall(lib(LibName), fuzz_library(LibName)),
    format('Fuzzing campaign complete. Results saved to fuzz_report.txt~n', []),
    halt.

setup_report :-
    open('fuzz_report.txt', write, Stream, [type(text)]),
    format(Stream, "========================================================================~n", []),
    format(Stream, "                DYNAMIC LIBRARY FUZZING RESULTS REPORT                   ~n", []),
    format(Stream, "========================================================================~n~n", []),
    close(Stream).

fuzz_library(LibName) :-
    sformat(LibPath, '/lib/~w', [LibName]),
    sformat(LibUsrPath, '/usr/lib/~w', [LibName]),
    (   exists_file(LibPath) -> Target = LibPath
    ;   exists_file(LibUsrPath) -> Target = LibUsrPath
    ;   Target = missing
    ),
    evaluate_target(Target, Status),
    append_report(LibName, Target, Status).

evaluate_target(missing, 'LibraryNotFound').
evaluate_target(Target, Status) :-
    Target \= missing,
    invoke_harness(Target, Status).

% Execute OS command safely falling back through available Trealla predicates
execute_cmd(Cmd) :- catch(system(Cmd), _, fail), !.
execute_cmd(Cmd) :- catch(shell(Cmd), _, fail), !.
execute_cmd(Cmd) :- catch(sh(Cmd), _, fail), !.

invoke_harness(Target, Status) :-
    sformat(Cmd, './fuzz_runner ~w > /tmp/fuzz_out.tmp 2>&1', [Target]),
    (   execute_cmd(Cmd) ->
        (   exists_file('/tmp/fuzz_out.tmp') ->
            setup_call_cleanup(
                open('/tmp/fuzz_out.tmp', read, Stream, [type(text)]),
                read_stream_to_status(Stream, Status),
                close(Stream)
            )
        ;   Status = 'ExecutionFailed'
        )
    ;   Status = 'ExecutionFailed'
    ).

% Recursively scan every line of the output until 'FailMode:' is found or EOF is hit.
read_stream_to_status(Stream, Status) :-
    read_line_to_string(Stream, Line),
    (   Line == end_of_file ->
        Status = 'UnknownError'
    ;   string(Line), sub_string(Line, 0, _, _, "FailMode: ") ->
        sub_string(Line, 10, _, 0, Status)
    ;   read_stream_to_status(Stream, Status)
    ).

append_report(LibName, TargetPath, Status) :-
    open('fuzz_report.txt', append, Stream, [type(text)]),
    format(Stream, "Library Target : ~w~n", [LibName]),
    format(Stream, "Input Domain   : ~w~n", [TargetPath]),
    (   Status == 'None' ->
        format(Stream, "Status         : WORKED (Functions initialized and executed cleanly)~n", []),
        format(Stream, "Details        : dlopen/dlclose completed with zero fatal signals or faults.~n", [])
    ;   Status == 'LibraryNotFound' ->
        format(Stream, "Status         : FAILED (Target Missing)~n", []),
        format(Stream, "Details        : Shared object binary does not exist within /lib or /usr/lib.~n", [])
    ;   format(Stream, "Status         : FAILED (~w)~n", [Status]),
        format(Stream, "Details        : Library functions failed under this input domain during dynamic evaluation.~n", [])
    ),
    format(Stream, "------------------------------------------------------------------------~n", []),
    close(Stream).