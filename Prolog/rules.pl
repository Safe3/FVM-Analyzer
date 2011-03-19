% Author:
% Date: 11/11/2010

%Rules
/*
disableProgram(X):-
    ntSetValueKey(X, debugger, '').
*/

disableProgram(X):-
    ntsetvaluekey(_, _, Y, 'debugger', ''),
    atom_concat('\\registry\\machine\\software\\microsoft\\windows nt\\currentversion\\image file execution options\\', X, Y).

disabledProgramsList(Programs) :-
    setof(Process, disableProgram(Process), Programs).

fileCreated(Behav, X):-
    ntcreatefile(_, _, _, X, created, _),
    isUnique(Behav, X).

listOfFilesCreated(Files):-
    setof(File, fileCreated('created', File), Files).

isUNC('unc').

remote(X) :-
    fileCreated('remote', X),
    sub_atom(X, 4, 3, Remaining, Sub),
    sub_atom(X, 7, Remaining, _, After),
    isUNC(Sub),
    %writeln(After),
    atom_concat('\\device\\lanmanredirector', After, Path),
    %writeln(Path),
    copyItself('remote-copy', Path).

remoteLocations(List) :-
    setof(X, remote(X), List).

% copy X to Y
checkCopy(Source, Destination) :-
    ntreadfile(_, _, _, Source, Buffer, _, _, BytesRead, _),
    ntwritefile(_, _, _, Destination, Buffer, _, _, BytesRead, _).

checkCopy(Source, Destination) :-
    atom_concat('\\??\\', NormalizedSrc, Source),
    copyfile(_, _, NormalizedSrc, Destination).

copyItselfTo(List) :-
  setof(Destination, copyItself('self-copy', Destination), List).

base(Destination) :-
    ntprocessimage(_, _, Source),
    checkCopy(Source, Destination).

copyItself(Behav, Destination) :-
    base(Destination),
    isUnique(Behav, Destination).

coyItself(Behav, Destination) :-
    copyItself(Source),
    checkCopy(Source, Destination),
    isUnique(Behav, Destination).

/*
autoRun(Key, Value, Data):-
    ntsetvaluekey(_, _, '\\registry\\machine\\software\\microsoft\\windows\\currentversion\\run', Value, Data),
    /*write(Key), */
    write('\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\'),
    write(Value), write(' = '), write(Data).
*/
    
autoRun(Key, Value, Data):-
    ntsetvaluekey(_, _, Key, Value, Data),
    atom_concat(_, '\\software\\microsoft\\windows\\currentversion\\run', Key),
    write(Key),
    write('\\'),
    write(Value), write(' = '), write(Data).
/*
autoRun(Key, Sid, Value, Data):-
    ntsetvaluekey(_, _, Key, Sid, 'software\\microsoft\\windows\\currentversion\\run', Value, Data),
    write('HKEY_USERS\\'), write(Sid), write('\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\'),
    write(Value), write(' = '), write(Data).
*/

autoStart:- autoRun(Key, Value, Data).
/*
autoStart:- autoRun(Key, Sid, Value, Data).
*/

/*
ntsetvaluekey(302934186422, 332, 'hkey_users', 's-1-5-21-725345543-299502267-2147187605-1003',
   'software\\microsoft\\windows\\currentversion\\run', 'microfost', 'c:\\windows\\system32\\hanny.exe').
*/

/*
analysis :-
    ((disabledProgramsList(Programs), write('List of Programs Disabled:'), nl, write(Programs), nl, nl) ; true) ,
    ((copyItselfTo(Locations), write('Self copying to locations:'), nl, write(Locations), nl, nl) ; true),
    ((listOfFilesCreated(Files), write('Creates following files:'), nl, write(Files), nl, nl) ; true).
*/

isKeyStrokeLogger('2').

hooking :-
     windowshook(_, _, Val),
     isKeyStrokeLogger(Val),
     write('Intercepts keyboard strokes'), nl, nl.

analysis :-
     disabledProgramsList(Programs),
     write('List of Programs Disabled:'),
     nl, write(Programs), nl, nl.

analysis :-
    copyItselfTo(Locations),
    write('Self copying to locations:'),
    nl, write(Locations), nl, nl.

analysis :-
    listOfFilesCreated(Files),
    write('Creates following files:'),
    nl, write(Files), nl, nl.

analysis :-
    remoteLocations(X),
    write('Copies itself to shared folders on the network'),
    nl, write(X), nl, nl.

analysis :-
    hooking, nl.

analysis :-
    autoStart, nl,
    write('Found Automatic Start Points:'), nl,
    fail.

:- dynamic ntreadfile/9, ntwritefile/9, ntcreatefile/6, ntsetvaluekey/5,
           copyfile/4, windowshook/3, ntprocessimage/3.

startAnalysis :- write('Starting High Level Malware Analysis:'), nl, nl,
    analysis,
    fail.

/*
startAnalysis :- myadd(3, 5, X).
*/    