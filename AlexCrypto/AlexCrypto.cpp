// AlexCrypto.cpp: 定义控制台应用程序的入口点。
//

#include "stdafx.h"


#include "exportInterface.h"
#include <iostream>
#include <fstream>
#include <string.h>
#include <stdio.h>
using namespace std;

char* ReadFile(string filename)
{
	char * buffer;
	long size;
	ifstream in(filename, ios::in | ios::binary | ios::ate);
	if (!in.is_open())
	{
		throw exception("Error opening file");
	}
	size = in.tellg();
	in.seekg(0, ios::beg);
	buffer = new char[size];
	in.read(buffer, size);
	in.close();

	return buffer;
}
void WriteFile(string name,string cdate)
{
	char buffer[256];
	ofstream out(name, ios::out);
	out << cdate.c_str() << endl;
	out.close();
	return;
}

int parse(string m)
{
	if (m.compare("-m"))
		return 1;
	if (m.compare("-c"))
		return 2;
	return -1;

}

int main(int argc , char* argv[])
{
	if (argc != 3)
	{
		cout << "param err!" << endl;
		return 0;
	}

	switch (parse(argv[1]))
	{
	case 1:
	{
		
		//EnDoCrypto(key,keylength,)
	}
		break;
	case 2:
	{

	}
		break;
	default:
		break;

	}
    return 0;
}

