% Author:
% Date: 11/11/2010

%Rules

/*******************************************************************************
List of keys created
*******************************************************************************/

key(X) :-
    ntcreatekey(_, _, X).

keyList :-
    key(X),
    addToResults('createdkey', X),
    fail.

/*******************************************************************************
List of disabled programs
*******************************************************************************/

disableProgram(X):-
    ntsetvaluekey(_, _, Y, 'debugger', ''),
    atom_concat('\\registry\\machine\\software\\microsoft\\windows nt\\currentversion\\image file execution options\\', X, Y).

disabledProgramsList :-
    disableProgram(Program),
    addToResults('disabled', Program),
    fail.
%setof(Process, disableProgram(Process), Programs).

/*******************************************************************************
List of files created
*******************************************************************************/

fileCreated(X):-
    ntcreatefile(_, _, _, X, created, _).
%    isUnique(Behav, X).

listOfFilesCreated :-
    fileCreated(File),
    addToResults('createfile', File),
    fail.
%setof(File, fileCreated('created', File), Files).

/*******************************************************************************
List of files modified
*******************************************************************************/
fileModified(X) :-
    ntcreatefile(_, _, _, X, opened, _),
    ntreadfile(_, _, _, X, _, _, _, _, _),
    ntwritefile(_, _, _, X, _, _, _, _, _),
    \+(fileCreated(X)).

listOfFilesModified :-
    fileModified(File),
    addToResults('modifiedfile', File),
    fail.
    
/*******************************************************************************
Self copying to remote shared folders
*******************************************************************************/

isUNC('unc').

remote(X) :-
    fileCreated(X),
    sub_atom(X, 4, 3, Remaining, Sub),
    sub_atom(X, 7, Remaining, _, After),
    isUNC(Sub),
    %writeln(After),
    atom_concat('\\device\\lanmanredirector', After, Path),
    %writeln(Path),
    copyItself(Path).

remoteLocations :-
    remote(File),
    addToResults('remote-copy', File),
    fail.
%setof(X, remote(X), List).

/*******************************************************************************
Copying to removable drives
*******************************************************************************/
removable(X) :-
    fileCreated(X),
    sub_atom(X, 4, 1, _, Drive),
    isremovable(_, _, Drive),
    copyItself(X).

removableLocations :-
    removable(File),
    addToResults('removable-copy', File),
    fail.
    


/*******************************************************************************
Self copying copy X to Y
*******************************************************************************/

checkCopy(Source, Destination) :-
    ntreadfile(_, _, _, Source, Buffer, _, _, BytesRead, _),
    ntwritefile(_, _, _, Destination, Buffer, _, _, BytesRead, _).

checkCopy(Source, Destination) :-
    atom_concat('\\??\\', NormalizedSrc, Source),
    copyfile(_, _, NormalizedSrc, Destination).

base(Destination) :-
    ntprocessimage(_, _, Source),
    checkCopy(Source, Destination).

copyItself(Destination) :-
    base(Destination).

coyItself(Destination) :-
    copyItself(Source),
    checkCopy(Source, Destination).

copyItselfToLocations :-
    copyItself(Destination),
    addToResults('self-copy', Destination),
    fail.
%setof(Destination, copyItself('self-copy', Destination), List).

/*******************************************************************************
Auto Start Extensibility points
*******************************************************************************/

autoRun(Key, Value, Data):-
    ntsetvaluekey(_, _, Key, Value, Data),
    atom_concat(_, '\\software\\microsoft\\windows\\currentversion\\run', Key).
    
autoStart:-
    autoRun(Key, Value, Data),
    atom_concat(Key, '\\', Temp1),
    atom_concat(Temp1, Value, Temp2),
    atom_concat(Temp2, ' = ', Temp3),
    atom_concat(Temp3, Data, Path),
    addToResults('auto-start', Path),
    fail.
    
/*
autoRun(Key, Sid, Value, Data):-
    ntsetvaluekey(_, _, Key, Sid, 'software\\microsoft\\windows\\currentversion\\run', Value, Data),
    write('HKEY_USERS\\'), write(Sid), write('\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\'),
    write(Value), write(' = '), write(Data).
*/

/*******************************************************************************
2655403719700, NtSetValueKey, 1424,
\Registry\Machine\Software\Classes\CLSID\{AF6B23D1-481E-425D-99A2-614F709FFEDD}\InprocServer32, ,
C:\WINDOWS\system32\3721.8.dll

Registers in-process server dll
*******************************************************************************/
isEmpty('').

registerInProcDll :-
    ntsetvaluekey(_, _, Key, Value, Path),
    atom_concat('\\registry\\machine\\software\\classes\\clsid\\', Clsid, Key),
    atom_concat(_, 'inprocserver32', Clsid),
    isEmpty(Value),
    addToResults('register-dll', Path),
    fail.
    
/*******************************************************************************
2655425839648, NtCreateKey, 1424,
\Registry\Machine\Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\{AF6B23D1-481E-425D-99A2-614F709FFEDD}
Registers a Browser Helper Object (Microsoft's Internet Explorer plugin module).
*******************************************************************************/

registerBHO :-
    ntcreatekey(_, _, ID),
    atom_concat('\\registry\\machine\\software\\microsoft\\windows\\currentversion\\explorer\\browser helper objects\\',
    Clsid, ID),
    addToResults('bho', Clsid),
    fail.
    
/*******************************************************************************
Process Creation
*******************************************************************************/
createProcess(PID, Path) :-
    ntcreateprocess(_, _, PID),
    ntprocessimage(_, PID, Path).

processList :-
    createProcess(PID, Path),
    atom_concat(PID, '$', Token),
    atom_concat(Token, Path, PIDPath),
    addToResults('createprocess', PIDPath),
    fail.

/*******************************************************************************
Dropper
*******************************************************************************/
dropper :-
    ntcreateprocess(_, _, PPID),
    ntprocessimage(_, PPID, ParentPath),
    ntcreateprocess(_, PPID, PID),
    ntdeletefile(_, PID, ParentPath, _),
    write('File at '),
    write(ParentPath),
    write(' is a Dropper'),
    nl, nl.

/*******************************************************************************
Hooking behaviors
*******************************************************************************/
isKeyStrokeLogger('2').

hooking :-
     windowshook(_, _, Val),
     isKeyStrokeLogger(Val),
     write('Intercepts keyboard strokes'), nl, nl.

/*******************************************************************************
Various Analysis rules one for each behavior
*******************************************************************************/

analysis :-
    keyList.

analysis :-
    dumpResult('createdkey','Registry keys created:').

analysis :-
    disabledProgramsList.
     /*write('List of Programs Disabled:'),
     nl, dumpResult('disabled'), nl, nl.
     */
analysis :-
    dumpResult('disabled', 'List of Programs Disabled:').

analysis :-
    listOfFilesCreated.
    /*
    write('Creates following files:'),
    nl, dumpResult('created'), nl, nl.
    */
analysis :-
    dumpResult('createfile', 'Creates following files:').

analysis :-
    listOfFilesModified.

analysis :-
    dumpResult('modifiedfile', 'Modifies following files:').
    
analysis :-
    copyItselfToLocations.
    /*
    write('Self copying to locations:'),
    nl, dumpResult('self-copy'), nl, nl.
    */
analysis :-
    dumpResult('self-copy', 'Self copying to locations:').


analysis :-
    remoteLocations.
    /*
    write('Copies itself to shared folders on the network'),
    nl, dumpResult('remote-copy'), nl, nl.
    */
analysis :-
    dumpResult('remote-copy', 'Copies itself to shared folders on the network:').
    
analysis :-
    removableLocations.
    /*
    write('Copies itself to removable drives'),
    nl, dumpResult('removable-copy'), nl, nl.
    */
analysis :-
    dumpResult('removable-copy', 'Copies itself to removable drives:').

analysis :-
    processList.
    
analysis :-
    dumpResult('createprocess', 'List of processes created:').

analysis :-
    dropper.

analysis :-
    hooking, nl.

analysis :-
    autoStart.

analysis :-
    dumpResult('auto-start', 'Automatic start points:').

analysis :-
    registerInProcDll.

analysis :-
    dumpResult('register-dll', 'Registers a in-process server DLL').

analysis :-
    registerBHO.

analysis :-
    dumpResult('bho', 'Registers a Browser Helper Object (an IE Plugin)').
/*
analysis :-
    autoStart, nl,
    write('Found Automatic Start Points:'), nl.
    %fail.
*/

:- dynamic ntreadfile/9, ntwritefile/9, ntcreatefile/6, ntsetvaluekey/5,
           copyfile/4, windowshook/3, ntprocessimage/3, isremovable/3,
           ntdeletefile/4, ntcreatekey/3.

startAnalysis :- write('Starting High Level Malware Analysis:'), nl, nl,
    analysis,
    fail.

/*
startAnalysis :- myadd(3, 5, X).
*/    