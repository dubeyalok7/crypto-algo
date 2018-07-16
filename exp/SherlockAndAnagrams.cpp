/*
 * SherlockAndAnagrams.cpp
 *
 *  Created on: 10-Aug-2018
 *      Author: napster
 */

#include <bits/stdc++.h>

using namespace std;

string sortStr(string s) {
	int ch[26]={0};
	string str;
	for(int i=0;i<s.length(); i++)
		ch[s[i]-'a']++;
	for(int i=0;i<26;i++)
		for(int j=0;j<ch[i];j++)
			str.push_back(i +'a');
	return str;
}

int findCnt(string s, string str, int idx){
	int cnt =0;
	for(int i = idx+1;i<s.length();i++){
		if(s[i]==str[0])
			cnt++;
	}
	return cnt;
}

void subString(string s, map<string, int> &m)
{
	if (s.length() > 1) {
		for (int i = 0; i < s.length(); i++) {
			for (int len = 1; len <= s.length() - i; len++) {
				string str = s.substr(i, len);
				if (str.length() > 1) {
					str = sortStr(str);

					if (m.find(str) == m.end()) {
						m.insert(make_pair(str, 1));
					} else
						m[str]++;
				}else{
					m.insert(make_pair(str,0));
					m[str] += findCnt(s,str,i);
				}
			}
		}
	}
}

// Complete the sherlockAndAnagrams function below.
int sherlockAndAnagrams(string s) {
	int cnt = 0;
	map<string, int> m;
	subString(s, m);
	map<string, int>::iterator itr;
	for(itr = m.begin(); itr != m.end(); ++itr){
		if(itr->second>1){
			if(itr->first.length()==1)
				cnt+= itr->second;
			else if(itr->second%2)
				cnt+= itr->second;
			else
				cnt+=itr->second/2;
		}
	}
	return cnt;
}

int SherlockAndAnagrams()
{
    int q;
    cin >> q;
    cin.ignore(numeric_limits<streamsize>::max(), '\n');

    for (int q_itr = 0; q_itr < q; q_itr++) {
        string s;
        getline(cin, s);
        int result = sherlockAndAnagrams(s);
        cout << result << "\n";
    }
    return 0;
}




