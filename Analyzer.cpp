// Analyzer.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

struct initParams
{
	HANDLE kernelLogFile;
	string userLogFileName;
	//HANDLE factsFile;
	//PlEngine *pEngine;
};

struct log 
{
	log(HANDLE hFile): logfile(hFile), dwTotalBytesRead(0), dwFileSize(0) {}
	HANDLE logfile;
	DWORD dwTotalBytesRead;
	DWORD dwFileSize;
	string strBuffer;
};

// critical section used for synchronizing all read and write access to the queue of log stmts
static CRITICAL_SECTION	critLogs;

// event used to wake the consumer thread
static HANDLE newLogsEvent;

// one and only initialization object
initParams initObj;

static int debug = 0;

deque<string> inputFacts;
vector<Fact> currentFacts;
vector<Fact> savedFacts;

#define	NUM_ARGS	4;

void
transformLog(string &log)
{
	//DWORD dwBytesWritten;
	if (log.find("NtOpenFile") != string::npos)
		return;

	Fact curr(log);
	currentFacts.push_back(curr);
	/*
	string temp(curr.getFact());
	temp.append("\r\n");
	WriteFile(initObj.factsFile, temp.data(), temp.size(), &dwBytesWritten, NULL);
	cout << "Bytes written" << dwBytesWritten << endl;
	*/
}

void
initProlog()
{
	// Initializing Prolog
	
	const int argc = NUM_ARGS;
	char **argv = new char*[argc];
	for (int i = 0; i < argc; ++i) {
		argv[i] = new char[32];
	}
	
    //strcpy_s(argv[0], 32, "swipl.dll");
	strcpy_s(argv[0], 32, "combined");
	strcpy_s(argv[1], 32, "-G32m");
	strcpy_s(argv[2], 32, "-L32m");
	strcpy_s(argv[3], 32, "-T32m");
	
	PL_initialise(argc, argv);

	if ( !PL_initialise(argc, argv) ) {
        PL_halt(1);
	}

	//initObj.pEngine = new PlEngine(argc, argv);
}

void
startAnalysis()
{

	// Initializing Prolog
	
	//initProlog();
	/*
	const int argc = NUM_ARGS;
	char **argv = new char*[argc];
	for (int i = 0; i < argc; ++i) {
		argv[i] = new char[32];
	}
	
    strcpy_s(argv[0], 32, "swipl.dll");
	strcpy_s(argv[1], 32, "-G32m");
	strcpy_s(argv[2], 32, "-L32m");
	strcpy_s(argv[3], 32, "-T32m");
	
	PL_initialise(argc, argv);

	if ( !PL_initialise(argc, argv) ) {
        PL_halt(1);
	}
	*/

	string prefix("consult('");
	string suffix("')");
	string rulesfile, factsfile;
	rulesfile = prefix + string("rules.pl") + suffix;
	factsfile = prefix + string("facts.pl") + suffix;

    //PlCall("pwd");
	//PlCall(rulesfile.c_str());

	HANDLE hFactsFile = CreateFile ("facts.pl", 
                      GENERIC_WRITE, 
                      0, 
                      NULL, 
                      CREATE_ALWAYS, 
                      FILE_ATTRIBUTE_NORMAL, 
                      NULL);
	
	if ( hFactsFile == INVALID_HANDLE_VALUE) {
		logerr(TEXT("CreateFile facts.pl"));
		ExitProcess(EXIT_FAILURE);
	}
	
	// Truncating facts.pl
	/*
	if (SetFilePointer(initObj.factsFile, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
		logerr(TEXT("SetFilePoinetr"));
		ExitProcess(EXIT_FAILURE);
	}

	if (SetEndOfFile(initObj.factsFile) == 0) {
		logerr(TEXT("SetEndOfFile"));
		ExitProcess(EXIT_FAILURE);
	}
	*/

	DWORD dwBytesWritten;
	vector<Fact>::iterator it;

	//sort(savedFacts.begin(), savedFacts.end());

	copy(savedFacts.begin(), savedFacts.end(), back_inserter(currentFacts));
	savedFacts.clear();

	/*
	for (it = savedFacts.begin(); it != savedFacts.end(); ++it) {
		string temp( (*it).getFact());
		temp.append("\r\n");
		WriteFile(hFactsFile, temp.data(), temp.size(), &dwBytesWritten, NULL);
	}
	*/

	sort(currentFacts.begin(), currentFacts.end());
	
	for (it = currentFacts.begin(); it != currentFacts.end(); ++it) {
		string temp( (*it).getFact());
		temp.append("\r\n");
		WriteFile(hFactsFile, temp.data(), temp.size(), &dwBytesWritten, NULL);
		if ( (*it).isRetain() == TRUE) {
			savedFacts.push_back(*it);
		}
	}
	currentFacts.clear();

	CloseHandle(hFactsFile);

	PlCall(factsfile.c_str());

	// no need to do this clear the results map
	//clearResultsMap();

	predicate_t p;
	int rval;

    p = PL_predicate( "startAnalysis", 0, NULL );
    rval = PL_call_predicate( NULL, PL_Q_NORMAL, p, NULL );

    //PL_halt( PL_toplevel() ? 0 : 1 );
}

// our thread that listens for events 
DWORD WINAPI 
processLog(LPVOID lpParameter)
{
	initProlog();

	while(1) {

		WaitForSingleObject(newLogsEvent, INFINITE);
		EnterCriticalSection(&critLogs);

		while (!inputFacts.empty()) {
			string log (inputFacts.front());
			inputFacts.pop_front();
			LeaveCriticalSection(&critLogs);

			transformLog(log);

			EnterCriticalSection(&critLogs);
		}

		LeaveCriticalSection(&critLogs);

		// pass facts to Prolog
		startAnalysis();
	}
	return 0;
}

// can return INVALID_HANDLE_VALUE
// for cases where the file has not been created
HANDLE 
openUserLogFile(HANDLE hFile)
{
	if (hFile != INVALID_HANDLE_VALUE) {
		return hFile;
	}

	HANDLE hUserLogFile = CreateFile (initObj.userLogFileName.c_str(), 
                      GENERIC_READ, 
                      FILE_SHARE_READ  | FILE_SHARE_WRITE, 
                      NULL, 
                      OPEN_EXISTING, 
                      FILE_ATTRIBUTE_NORMAL, 
                      NULL);
	return hUserLogFile;
}

BOOL 
initialize( TCHAR *fvmname, TCHAR *logfile = NULL)
{
	string fvmRegPath(IDS_REG_VMS);
	fvmRegPath += string("\\") + string(fvmname);
    LONG lResult;
    DWORD dwSize;
    TCHAR szRoot[MAX_PATH + 1];
	TCHAR szID[64];
    HKEY hKey;
	HANDLE hFile;
	string kernelLogFilename;
	string userLogFilename;

	if (debug == 0) {
		lResult = RegOpenKeyEx (HKEY_CURRENT_USER, fvmRegPath.c_str(), 0, KEY_READ, &hKey);
		
		if (lResult != ERROR_SUCCESS) {
			logerr(TEXT("RegOpenKey"), lResult);
			return FALSE;
		}
		
		dwSize = sizeof(szRoot);
		lResult = RegQueryValueEx(	hKey, TEXT("fvmroot"), 
									NULL, NULL,
									(LPBYTE) szRoot, &dwSize );
		
		if (lResult != ERROR_SUCCESS) {
			logerr(TEXT("RegQueryValueEx fvmroot"), lResult);
			return FALSE;
		}
		
		dwSize = sizeof(szID);
		lResult = RegQueryValueEx(	hKey, TEXT("fvmid"),
									NULL, NULL,
									(LPBYTE) szID, &dwSize );
		
		if (lResult != ERROR_SUCCESS) {
			logerr(TEXT("RegQueryValueEx fvmid"), lResult);
			return FALSE;
		}
		
		RegCloseKey(hKey);
		
		string separator("\\");
		kernelLogFilename = szRoot + separator + szID + string(".log");
		cout << "Kernel log file is: " << kernelLogFilename << endl;

		userLogFilename = szRoot + separator + szID + separator + string(USER_LOG_FILE);
		cout << "User log file is: " << userLogFilename << endl;
		initObj.userLogFileName = userLogFilename;
	}
	else {
		kernelLogFilename = logfile;
	}

	hFile = CreateFile (kernelLogFilename.c_str(), 
                      GENERIC_READ, 
                      FILE_SHARE_READ  | FILE_SHARE_WRITE, 
                      NULL, 
                      OPEN_EXISTING, 
                      FILE_ATTRIBUTE_NORMAL, 
                      NULL);
	
	if ( hFile == INVALID_HANDLE_VALUE) {
		logerr(TEXT("CreateFile"));
		return FALSE;
	}
	initObj.kernelLogFile = hFile;

	InitializeCriticalSection(&critLogs);
	newLogsEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	CreateThread(NULL, 0, processLog, NULL, 0, NULL);

	return TRUE;
}

static DWORD parseBuffer(string &strBuffer)
{
	size_t startPos = 0, endPos;
	int length;
	string s;

	DWORD bytesLeft = 0;
	BOOL newLog = FALSE;

	EnterCriticalSection(&critLogs);
	while ( (endPos = strBuffer.find("\r\n", startPos)) != string::npos) {	// when u write \n to a file, windows automatically writes \r\n
		length = endPos - startPos;
		inputFacts.push_back(strBuffer.substr(startPos, length));
		newLog = TRUE;
		//s = strBuffer.substr(startPos, length);
		//cout << s << endl;
		startPos = endPos + 2;
	}
	LeaveCriticalSection(&critLogs);

	if (newLog == TRUE)
		SetEvent(newLogsEvent);

	// check if we have consumed all the bytes in the buffer
	if (startPos != string::npos) { 
		string partialLine = strBuffer.substr(startPos);
		strBuffer.assign(partialLine);
		bytesLeft = strBuffer.size();
	}
	else {
		strBuffer.clear();
	}

	return bytesLeft;
}

void
readFromLog(log &logObj)
{
	DWORD dwFileSize;
	DWORD dwBytesRead = 0;
	BOOL bReadOk;
	TCHAR buffer[SIZE + 1];

	dwFileSize = GetFileSize (logObj.logfile, NULL);
	logObj.dwTotalBytesRead;
	while (logObj.dwTotalBytesRead < dwFileSize) {
		bReadOk = ReadFile(logObj.logfile, buffer, SIZE, &dwBytesRead, NULL);
		if (!bReadOk) {
			logerr(TEXT("ReadFile"));
			exit(EXIT_FAILURE);
		}
		buffer[dwBytesRead] = 0;
		// use append because there might be some bytes left over in the buffer in case of partial records
		// Append also works if the buffer is empty
		logObj.strBuffer.append(buffer, dwBytesRead);
		logObj.dwTotalBytesRead += dwBytesRead;
		parseBuffer(logObj.strBuffer);
	}
}

void preprocess()
{
	log kernelObj(initObj.kernelLogFile);
	log userObj(INVALID_HANDLE_VALUE);

	populateFacts(savedFacts);

	while (1) {

		readFromLog(kernelObj);
		userObj.logfile = openUserLogFile(userObj.logfile);
		if (userObj.logfile != INVALID_HANDLE_VALUE) {
			readFromLog(userObj);
		}

		Sleep(5000);
	}
	//PL_halt(0);
}

int _tmain(int argc, _TCHAR* argv[])
{
	if ( argc != 2 ) {
		cout << "Usage: " << argv[0] << " <fvm name> " << endl;
		exit(EXIT_FAILURE);
	}

	if (strstr(argv[1], ".log") != NULL) {
		debug = 1;
		initialize("dummy", argv[1]);
	}
	else if ( initialize(argv[1]) == FALSE) {
		debug = 0;
		cout << "Failed to intialize analyzer" << endl;
		exit(EXIT_FAILURE);
	}
	
	preprocess();

	CloseHandle(initObj.kernelLogFile);
	//CloseHandle(initObj.userLogFile);
	int a;
	cin >> a;
	return 0;
}