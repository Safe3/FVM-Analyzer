#pragma once

class Fact
{
public:
	enum FactType {
		NT_CREATE_PROCESS = 0,
		NT_PROCESS_IMAGE,
		NT_OPEN_FILE,
		NT_CREATE_FILE,
		NT_READ_FILE,
		NT_DELETE_FILE = 5,
		NT_CREATE_KEY,
		NT_SET_VALUE_KEY,
		NT_WRITE_FILE,
		WIN32_COPY_FILE,
		WIN32_HOOK = 10,
		WIN32_REMOVABLE_DIR,
		NT_UNKNOWN_TYPE
	};
	
	Fact(std::string &log);
	
	const string& getFact() { return fact; }
	bool isRetain() { return retain; }
	int getArgs() { return nargs; }
	bool operator < (const Fact &rhs) {
		return (fact < rhs.fact);
	}

private:
	FactType type;
	string fact;
	int	nargs;
	bool retain;

	static FactType getSyscallType(const string &instr);
	void setIsRetain();
	static void normalize(string &str);
};