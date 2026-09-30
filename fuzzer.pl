:- use_module(library(system)).
:- use_module(library(iso_ext)).

sformat(String, Format, Args) :-
    (   is_list(Args) -> format(string(String), Format, Args)
    ;   format(string(String), Format, [Args])
    ).

main :-
    setup_report,
    format('Starting Exhaustive Alpine Fuzzing Campaign~n', []),
    exhaustively_fuzz_all,
    format('Fuzzing campaign complete.~n', []),
    halt.

setup_report :-
    open('fuzz_report.txt', write, Stream, [type(text)]),
    format(Stream, "========================================================================~n", []),
    format(Stream, "                EXHAUSTIVE DYNAMIC FUZZING REPORT                       ~n", []),
    format(Stream, "========================================================================~n~n", []),
    close(Stream).

exhaustively_fuzz_all :-
    execute_cmd('find /lib /usr/lib /bin /sbin /usr/bin /usr/sbin -name "*.so*" -o -name "*.exe" -type f > /tmp/all_binaries.list'),
    setup_call_cleanup(
        open('/tmp/all_binaries.list', read, Stream, [type(text)]),
        process_stream_lines(Stream),
        close(Stream)
    ).

process_stream_lines(Stream) :-
    (   at_end_of_stream(Stream) -> true
    ;   read_line_to_codes(Stream, Codes),
        (   Codes == end_of_file -> true
        ;   Codes \== [] ->
            atom_codes(LibPath, Codes),
            (   LibPath \== '' ->
                catch(fuzz_library(LibPath), _, true)
            ;   true
            ),
            process_stream_lines(Stream)
        ;   process_stream_lines(Stream)
        )
    ).

fuzz_library(Target) :-
    evaluate_target(Target, Status, DurationUs),
    append_report(Target, Target, Status, DurationUs).

evaluate_target(Target, 'SystemCoreLibrary', 0) :-
    (   sub_atom(Target, _, _, _, 'ld-musl')
    ;   sub_atom(Target, _, _, _, 'libc.musl')
    ), !.
evaluate_target(Target, Status, DurationUs) :-
    (   check_file_exists(Target) ->
        invoke_harness(Target, Status, DurationUs)
    ;   Status = 'LibraryNotFound', DurationUs = 0
    ).

check_file_exists(Path) :- catch(file_exists(Path), _, fail), !.
check_file_exists(Path) :- catch(exists_file(Path), _, fail), !.

execute_cmd(Cmd) :- catch(system(Cmd), _, fail), !.
execute_cmd(Cmd) :- catch(shell(Cmd), _, fail), !.

invoke_harness(Target, Status, DurationUs) :-
    sformat(Cmd, '/usr/local/bin/fuzz_runner ~w > /tmp/fuzz_out.tmp 2>&1', [Target]),
    (   execute_cmd(Cmd) ->
        (   check_file_exists('/tmp/fuzz_out.tmp') ->
            setup_call_cleanup(
                open('/tmp/fuzz_out.tmp', read, Stream, [type(text)]),
                read_stream_to_metrics(Stream, 'UnknownError', 0, Status, DurationUs),
                close(Stream)
            )
        ;   Status = 'ExecutionFailed', DurationUs = 0
        )
    ;   Status = 'ExecutionFailed', DurationUs = 0
    ).

read_stream_to_metrics(Stream, AccStatus, AccDuration, Status, DurationUs) :-
    (   at_end_of_stream(Stream) -> Status = AccStatus, DurationUs = AccDuration
    ;   read_line_to_codes(Stream, Codes),
        (   Codes == end_of_file -> Status = AccStatus, DurationUs = AccDuration
        ;   atom_codes(AtomLine, Codes),
            (   parse_fail_mode(AtomLine, ParseStatus) -> read_stream_to_metrics(Stream, ParseStatus, AccDuration, Status, DurationUs)
            ;   parse_duration(AtomLine, ParseDuration) -> read_stream_to_metrics(Stream, AccStatus, ParseDuration, Status, DurationUs)
            ;   read_stream_to_metrics(Stream, AccStatus, AccDuration, Status, DurationUs)
            )
        )
    ).

parse_fail_mode(AtomLine, Status) :-
    sub_atom(AtomLine, 0, 10, _, 'FailMode: '),
    sub_atom(AtomLine, 10, _, 0, RawStatus),
    atom_codes(RawStatus, Codes0),
    exclude(is_whitespace_code, Codes0, Codes),
    atom_codes(Status, Codes).

parse_duration(AtomLine, DurationUs) :-
    sub_atom(AtomLine, 0, 17, _, 'ExecutionTimeUs: '),
    sub_atom(AtomLine, 17, _, 0, RawDuration),
    atom_codes(RawDuration, Codes0),
    exclude(is_whitespace_code, Codes0, Codes),
    number_codes(DurationUs, Codes).

is_whitespace_code(C) :- C =< 32.

append_report(LibName, TargetPath, Status, DurationUs) :-
    open('fuzz_report.txt', append, Stream, [type(text)]),
    format(Stream, "Library Target : ~w~n", [LibName]),
    format(Stream, "Input Domain   : ~w~n", [TargetPath]),
    format(Stream, "Execution Time : ~w us~n", [DurationUs]),
    (   Status == 'None' -> StatText = 'WORKED', Details = 'dlopen/dlclose completed cleanly.'
    ;   Status == 'LibraryNotFound' -> StatText = 'FAILED (Target Missing)', Details = 'Shared object binary missing.'
    ;   Status == 'SystemCoreLibrary' -> StatText = 'SKIPPED', Details = 'Bypassed core musl runtime.'
    ;   sformat(StatText, 'FAILED (~w)', [Status]), Details = 'Failed dynamic execution under domain.'
    ),
    format(Stream, "Status         : ~w~n", [StatText]),
    format(Stream, "Details        : ~w~n", [Details]),
    format(Stream, "------------------------------------------------------------------------~n", []),
    close(Stream),
    % Emits dynamic JSON event for live streaming
    format('FUZZ_RESULT:{"target":"~w","domain":"~w","status":"~w","duration_us":~w,"details":"~w"}~n', [LibName, TargetPath, StatText, DurationUs, Details]).

:- initialization(main).