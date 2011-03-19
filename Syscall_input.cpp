#include "stdafx.h"
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/replace.hpp>

void 
Fact::normalize(string &source)
{
	string old("\\");
	string target("\\\\");
	boost::replace_all(source, old, target);
	//string normalized;
	//str.replace(str.begin(), str.end(), '\\', '\\');
}

Fact::Fact(string &log)
{

	// convert log to lower case
	boost::to_lower(log);

	// tokenize
	vector<string> tokens;
	boost::split(tokens, log, boost::is_any_of(","));

	// Remove leading and trailing whitespaces
	for ( vector<string>::iterator it = tokens.begin(); it != tokens.end(); ++it ) {
		boost::algorithm::trim(*it);
	}

	// Initialize retain to FALSE
	retain = FALSE;

	string syscall = tokens[1];
	type = getSyscallType(syscall);
	if (type == NT_UNKNOWN_TYPE)
		exit(EXIT_FAILURE);

	nargs = tokens.size() - 1;

	string ts = tokens[0];
	string pid = tokens[2];

	string separator = ", ";

	fact = syscall + string("(");
	fact += ts + separator + string("'") + pid + string("'");

	for ( int i = 3; i <= nargs ; ++i) {
		normalize(tokens[i]);
		fact += separator + string("'") + tokens[i] + string("'") ;
	}
	fact += string(").");

	setIsRetain();

	//ntSetValueKey(302934186422, 332, 'hkey_users', 's-1-5-21-725345543-299502267-2147187605-1003',
   //'software\\microsoft\\windows\\currentversion\\run', 'microfost', 'c:\\windows\\system32\\hanny.exe').

}

Fact::FactType Fact::getSyscallType(const string &instr)
{

	/*
	NT_CREATE_PROCESS = 0,
	NT_PROCESS_IMAGE,
	NT_OPEN_FILE,
	NT_CREATE_FILE,
	NT_READ_FILE,
	NT_CREATE_KEY = 5,
	NT_SET_VALUE_KEY,
	NT_WRITE_FILE,
	NT_UNKNOWN_TYPE
	*/
	FactType retval;
	
	if (instr == "ntcreateprocess") {
		retval = NT_CREATE_PROCESS;
	}
	else if (instr == "ntprocessimage") {
		retval = NT_PROCESS_IMAGE;
	}
	else if (instr == "ntopenfile") {
		retval = NT_OPEN_FILE;
	}
	else if (instr == "ntcreatefile") {
		retval = NT_CREATE_FILE;
	}
	else if (instr == "ntreadfile") {
		retval = NT_READ_FILE;
	}
	else if (instr == "ntdeletefile") {
		retval = NT_DELETE_FILE;
	}
	else if (instr == "ntcreatekey") {
		retval = NT_CREATE_KEY;
	}
	else if (instr == "ntsetvaluekey") {
		retval = NT_SET_VALUE_KEY;
	}
	else if (instr == "ntwritefile") {
		retval = NT_WRITE_FILE;
	}
	else if (instr == "copyfile") {
		retval = WIN32_COPY_FILE;
	}
	else if (instr == "windowshook") {
		retval = WIN32_HOOK;
	}
	else if (instr == "isremovable") {
		retval = WIN32_REMOVABLE_DIR;
	}
	else {
		cout << "Unknown syscall: " << instr << endl;
		retval = NT_UNKNOWN_TYPE;
	}

	return retval;
}

void Fact::setIsRetain()
{
	if (	(type == NT_CREATE_FILE)	|| 
			(type == NT_READ_FILE)		|| 
			(type == NT_WRITE_FILE)		|| 
			(type == NT_PROCESS_IMAGE)	||
			(type == NT_CREATE_PROCESS) ||
			(type == WIN32_REMOVABLE_DIR) 
		) {
			retain = TRUE;
	}
	else {
		retain = FALSE;
	}

}