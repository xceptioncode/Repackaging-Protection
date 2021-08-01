import json, os, sys
from collections import Counter

if (len(sys.argv) < 2 or len(sys.argv) > 2):
	print("""\nThis script aggregates the collected stats the given package.\n\n Usage: %s packageDir \n\n Example: %s org_mozilla_rocket/\n""" %(sys.argv[0], sys.argv[0]));
	exit();

dir = sys.argv[1];

def load_previous_stats_Min():
        try:
                with open(dir + "/aggDataMin.txt") as data_file:
                        statsMap = json.load(data_file);
                        return(statsMap);
        except Exception as e:
		statsMap = {};
                return statsMap;


def load_previous_stats_All():
        try:
                with open(dir + "/aggDataAll.txt") as data_file:
                        statsMap = json.load(data_file);
                        return(statsMap);
        except Exception as e:
                statsMap = {};
                return statsMap;


def merge_dicts(d1, d2):
	z = d1.copy()
	z.update(d2)
	return z

def remove_random(D):
	nonRandomD = {};
	for k in D.keys():
		newK = k.split("_");
		del newK[-1];
		newK = "_".join(newK);
		if newK in nonRandomD:
			if int(nonRandomD[newK]) < int(D[k]):
				nonRandomD[newK] = D[k];
				continue;
			else:
				continue;
		nonRandomD[newK] = D[k];

	return nonRandomD;

def combine_dicts_max(a, b):
	return dict(a.items() + b.items() + [(k, (a[k] if a[k] > b[k] else b[k])) for k in set(b) & set(a)])

def combine_dicts_sum(a, b):
	return dict(a.items() + b.items() + [(k, int(a[k]) + int(b[k])) for k in set(b) & set(a)])

found_new_stats = False;
statsMapMin = load_previous_stats_Min();
statsMapAll = load_previous_stats_All();
for root, dirs, files in os.walk(dir):
	for f in files:
		if f.endswith(".json"):
			found_new_stats = True;
			with open(dir + f) as data_file:
				data = json.load(data_file);
				data = remove_random(data);
				statsMapMin = combine_dicts_max(statsMapMin, data);
				statsMapAll = combine_dicts_sum(statsMapAll, data);
			os.remove(dir + f);


if (found_new_stats):
	aggData = open(dir + "/aggDataMin.txt", "w");

	json.dump(statsMapMin, aggData);

	aggData.close();

        aggData = open(dir + "/aggDataAll.txt", "w");

        json.dump(statsMapAll, aggData);

        aggData.close();

	print("[Success] New stats aggregated!");
else:
	print("[Error] No new stats found!");
