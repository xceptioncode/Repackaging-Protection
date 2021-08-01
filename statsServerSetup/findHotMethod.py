import json, os, sys, operator
from collections import Counter

if (len(sys.argv) < 3 or len(sys.argv) > 3):
        print("""\nThis script finds and saves the top hot methods based on given percentage (e.g., 10) for the given package.\n\n Usage: %s packageDir percentage \n\n Example: %s org_mozilla_rocket/ 10\n""" %(sys.argv[0], sys.argv[0]));
        exit();

dir = sys.argv[1];
prct = sys.argv[2];
prct = float(prct)

def load_previous_stats():
	try:
		with open(dir + "/aggDataMin.txt") as data_file:
			statsMapMin = json.load(data_file);
		with open(dir + "/aggDataAll.txt") as data_file:
                        statsMapAll = json.load(data_file);
                        return(statsMapMin, statsMapAll);
	except Exception as e:
		print("[Error] Aggregated data not found. Run aggregator first!");
		exit();

statsMapMin, statsMapAll = load_previous_stats();

for k in statsMapMin.keys():
	statsMapMin[k] = int(statsMapMin[k])

for k in statsMapAll.keys():
        statsMapAll[k] = int(statsMapAll[k])



sorted_statsMapMin = sorted(statsMapMin.items(), key=operator.itemgetter(1));

sorted_statsMapAll = sorted(statsMapAll.items(), key=operator.itemgetter(1));

hotMethodsMin = sorted_statsMapMin[int(len(sorted_statsMapMin) * (1-(prct/2)/100)) : int(len(sorted_statsMapMin) * 1)]

hotMethodsAll = sorted_statsMapAll[int(len(sorted_statsMapAll) * (1-(prct - prct/2)/100)) : int(len(sorted_statsMapAll) * 1)]

def print_hotMethods(hotMethodMin, hotMethodAll):
	hotMethodsFile = open(dir + "/hotMethods_" + str(int(prct)) + "_prct.list", "w");

	for i in range(0, len(hotMethodMin)):
		hotMethodsFile.write(hotMethodMin[i][0] + "\n");

	for i in range(0, len(hotMethodAll)):
                hotMethodsFile.write(hotMethodAll[i][0] + "\n");

	hotMethodsFile.close();
	print("[Success] Saved HotMethods list in " + dir);

print_hotMethods(hotMethodsMin, hotMethodsAll);
