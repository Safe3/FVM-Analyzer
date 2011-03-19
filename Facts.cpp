#include "stdafx.h"


static void populateRemovableDrive(vector<Fact> &savedFacts)
{
	TCHAR szTemp[SIZE];
	szTemp[0] = '\0';

	if (GetLogicalDriveStrings(SIZE - 1, szTemp)) 
	{
		TCHAR szDrive[4] = TEXT(" :\\");
		TCHAR* p = szTemp;
		UINT driveType;
		string prefix("NA, isRemovable, NA,");
		do {
			// Copy the drive letter to the template string
            *szDrive = *p;
			driveType = GetDriveType(szDrive);
			if (driveType == DRIVE_REMOVABLE) {
				string strfact(prefix);
				//strfact = prefix + string("\\??\\") + string(szDrive);
				//prefix.append(szDrive[0]);
				//strfact = prefix + string(szDrive[0]);
				strfact.push_back(szDrive[0]);
				cout << strfact << endl;
				Fact currFact(strfact);
				savedFacts.push_back(currFact);
			}
            // Go to the next NULL character.
            while (*p++);
		} while (*p); // end of string
	}
}

// populate facts for all malwares
void populateFacts(vector<Fact> &savedFacts)
{
	populateRemovableDrive(savedFacts);
}