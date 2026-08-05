:- use_module(library(system)).
:- use_module(library(iso_ext)).
:- catch(consult('alpine_libs.pl'), _, true).

sformat(String, Format, Args) :-
    (   is_list(Args) -> format(string(String), Format, Args)
    ;   format(string(String), Format, [Args])
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
    resolve_target(LibName, Target),
    evaluate_target(Target, Status),
    append_report(LibName, Target, Status).

% Target Path Resolution Strategy
resolve_target(LibName, Target) :-
    (   check_file_exists(LibName) ->
        Target = LibName
    ;   sformat(LibPath, '/lib/~w', [LibName]),
        check_file_exists(LibPath) ->
        Target = LibPath
    ;   sformat(LibUsrPath, '/usr/lib/~w', [LibName]),
        check_file_exists(LibUsrPath) ->
        Target = LibUsrPath
    ;   Target = missing
    ), !.

check_file_exists(Path) :- catch(file_exists(Path), _, fail), !.
check_file_exists(Path) :- catch(exists_file(Path), _, fail), !.

evaluate_target(missing, 'LibraryNotFound').
evaluate_target(Target, Status) :-
    Target \= missing,
    invoke_harness(Target, Status).

% Safe execution fallback for Trealla system interfaces
execute_cmd(Cmd) :- catch(system(Cmd), _, fail), !.
execute_cmd(Cmd) :- catch(shell(Cmd), _, fail), !.

invoke_harness(Target, Status) :-
    sformat(Cmd, './fuzz_runner ~w > /tmp/fuzz_out.tmp 2>&1', [Target]),
    (   execute_cmd(Cmd) ->
        (   check_file_exists('/tmp/fuzz_out.tmp') ->
            setup_call_cleanup(
                open('/tmp/fuzz_out.tmp', read, Stream, [type(text)]),
                read_stream_to_status(Stream, Status),
                close(Stream)
            )
        ;   Status = 'ExecutionFailed'
        )
    ;   Status = 'ExecutionFailed'
    ).

read_stream_to_status(Stream, Status) :-
    (   at_end_of_stream(Stream) ->
        Status = 'UnknownError'
    ;   read_line_to_string(Stream, Line),
        (   Line == end_of_file ->
            Status = 'UnknownError'
        ;   parse_fail_mode(Line, Status) ->
            true
        ;   read_stream_to_status(Stream, Status)
        )
    ).

% Robust line parsing for dynamic execution statuses
parse_fail_mode(Line, Status) :-
    atom_string(AtomLine, Line),
    sub_atom(AtomLine, 0, 10, _, 'FailMode: '),
    sub_atom(AtomLine, 10, _, 0, StatusAtom),
    atom_string(StatusAtom, Status).

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


:- initialization(main).