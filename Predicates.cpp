#include "stdafx.h"

//static set<DWORD>results;
struct resultsData
{
	bool	show;
	string	value;

	resultsData(): value("") {
		show = true;
	}

	resultsData(bool flag, const string &strVal) : value(strVal) {
		show = flag;
	}

	/*
	bool operator < (const resultsData &rhs) const {
		return value < rhs.value ;
	}
	*/
};


struct mycomp
{
	bool operator() (const resultsData& lhs, const resultsData& rhs)
	{
		return lhs.value < rhs.value;
	}
};


typedef set<resultsData, mycomp> resultsObj;
//typedef set<resultsData> resultsObj;
//typedef map<string, set<resultsData, mycomp> > resultsMap;
typedef map<string, resultsObj > resultsMap;

// the one and only global object
resultsMap results;

DWORD computeSum(const char* buffer, size_t len)
{
	return 0;
}

VOID clearResultsMap()
{
	//results.clear();
}

/*
PREDICATE(isUnique, 2)
{ 
	BOOL retval;
	char *behavior = (char*)_av[0];
	char *filename = (char*)_av[1];
	string strbehavior(behavior);
	string strfilename(filename);
	
	resultsMap::iterator it;
	
	it = results.find(strbehavior);
	
	if (it == results.end()) {
		set<string> resultSet;
		resultSet.insert(strfilename);
		results.insert(make_pair(strbehavior, resultSet));
		retval = TRUE;
	}
	else {
		pair<set<string>::iterator, bool> ret;
		ret = (*it).second.insert(strfilename);
		retval = ret.second;
	}

	return retval;
}
*/

PREDICATE(addToResults, 2)
{ 
	BOOL retval;
	char *behavior = (char*)_av[0];
	char *value = (char*)_av[1];
	string strbehavior(behavior);
	string strvalue(value);
	
	resultsMap::iterator it;
	
	it = results.find(strbehavior);
	
	//cout << "Behavior: " << behavior << " Value: " << value << endl;

	if (it == results.end()) {
		//set<string> resultSet;
		//set<resultsData, mycomp> resultSet;
		resultsObj resultSet;
		resultsData data(true, strvalue);
		//resultSet.insert(strvalue);
		resultSet.insert(data);
		results.insert(make_pair(strbehavior, resultSet));
		retval = TRUE;
	}
	else {
		//pair<set<string>::iterator, bool> ret;
		//pair<set<resultsData, mycomp>::iterator, bool> ret;
		pair<resultsObj::iterator, bool> ret;
		resultsData data(false, strvalue);
		//ret = (*it).second.insert(strvalue);
		ret = (*it).second.insert(data);
		if (ret.second == true) {
			(*ret.first).show = true;
		}
		retval = ret.second;
	}

	return retval;
}

PREDICATE(dumpResult, 2)
{ 
	BOOL retval;
	char *behavior = (char*)_av[0];
	char *caption = (char*)_av[1];
	string strbehavior(behavior);
	string strcaption(caption);
	
	resultsMap::iterator it;
	
	it = results.find(strbehavior);
	
	//cout << "Dumping results for: " << strbehavior << endl;

	if (it == results.end()) {
		//cout << "Error: Behaviour not found !!!" << endl << endl;
		retval = FALSE;
	}
	else {
		cout << strcaption << endl;
		//set<string>::iterator resultsIter;
		//set<resultsData, mycomp>::iterator resultsIter;
		resultsObj::iterator resultsIter;
		for (resultsIter = (*it).second.begin(); resultsIter != (*it).second.end(); ++resultsIter) {
			if ( (*resultsIter).show == true ) {
				cout << (*resultsIter).value << endl;
				(*resultsIter).show = false;
			}
		}
		//(*it).second.clear();
		cout << endl << endl;
		retval = TRUE;
	}

	return retval;
}