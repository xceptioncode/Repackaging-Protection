import sys, os, subprocess
from difflib import SequenceMatcher

"""
This script compare logs inorder to fnd unique errors in the protected version of the application in comparison to the original application logs. 
This was used in order to find and fix the new runtime errors generated after embeding the repackaging detection capability to the application. Due to extended information collection, we could also differentiate between different errors (errors due to bugs in SOOT framework, our instrumentation, etc).
"""

if (len(sys.argv) < 2 or len(sys.argv) > 2):
        print("""\nThis script run test to compare logs inorder to find unique errors.\n\n Usage: %s packageDir \n\n Example: %s org_mozilla_rocket/\n""" %(sys.argv[0], sys.argv[0]));
        exit();

dir = sys.argv[1];

processInfo = open("processInfo.txt", "r");
toVerify = open("verify_these_exception.txt", "a");
success = open("successful_test_exception.txt", "a");

print "Running exception comparison test: "

for Line in processInfo:
		line = Line.split("----");
		folder = line[0].replace(" ", "_").replace(".", "_").replace("/", '') + "_transformed";
		if line[1] == "transformed":
				pid = int(line[2]);
				tPid = pid;
				cmd = "awk /" + str(pid) + "/ data/" + folder + "/logcat.txt | grep -i 'exception\|java.lang.*error' | awk '{$1=$2=$3=$4=$5=\"\"; print $0}'"
				try:
						output1 = subprocess.check_output(['bash', '-c', cmd]);
				except subprocess.CalledProcessError, e:
						output1 = 0;
				#print output1
				line = processInfo.next().split("----");
				if line[1] == "original":
						pid = int(line[2]);								
						cmd = "awk /" + str(pid) + "/ data/" + folder.replace("_transformed", "_original") + "/logcat.txt | grep -i 'exception\|java.lang.*error' | awk '{$1=$2=$3=$4=$5=\"\"; print $0}'"
						try:
								output2 = subprocess.check_output(['bash', '-c', cmd]);
						except subprocess.CalledProcessError, e:
								output2 = 0;
						#print output2
						
						if (output1 == "\n" or output2 == "\n") or (tPid == pid):
								cmd = "cat data/" + folder + "/logcat.txt | grep -i 'ExceptionInInitializerError' | wc -l"
								cmd1 = "cat data/" + folder.replace("_transformed", "_original") + "/logcat.txt | grep -i 'ExceptionInInitializerError' | wc -l"
								initErrorCount1 = 0;
								initErrorCount2 = 0;
								try:
										initErrorCount1 = subprocess.check_output(['bash', '-c', cmd]);
										initErrorCount2 = subprocess.check_output(['bash', '-c', cmd1]);
								except subprocess.CalledProcessError, e:
										pass					
								if (int(initErrorCount1) > int(initErrorCount2)):
										print "\t[+] " + line[0] + " - Success"
										success.write(line[0] + "\n");
						elif output1 == output2:  # compare directly
								print "\t[+] " + line[0] + " - Success"
								success.write(line[0] + "\n");
						elif "java.lang.ExceptionInInitializerError" in output1: # Soot internal Error
								print "\t[+] " + line[0] + " - Success"
								success.write(line[0] + "\n");
						elif "Unresolved compilation error" in output1 and (not "Unresolved compilation error" in output2): # Soot body.validate internal error
								print "\t[+] " + line[0] + " - Success"
								success.write(line[0] + "\n");
						else:
								"""
								same = set(output1).difference(output2) # compare even if position changed
								if len(same) > 0: # Found unique items
										print "\t[-] " + line[0] + " - Verify"
										toVerify.write(line[0] + "\n");		
										print output1
										print output2
										print "\n same: " +  str(same)
								else:
										print "\t[+] " + line[0] + " - Success"
										success.write(line[0] + "\n");
								"""
								"""
								if len(output1) > len(output2):
										#res = output1.replace(output2, '')
										if len(output2) > 0:
												res = ' '.join(output1.split(output2))
								else:
										#res = output2.replace(output1, '')
										if len(output1) > 0:
												res = ' '.join(output2.split(output1))
								"""
								s1 = set(output1.split("\n"))
								s2 = set(output2.split("\n"))
								res = s1.difference(s2)
								res = ''.join(res)
								
								# because of randomized string - optimal treatment with a number of manual verification
								if "java.lang.ClassNotFoundException" in res and  "java.lang.ClassNotFoundException" in output2:
										print "\t[+] " + line[0] + " - Success"
										success.write(line[0] + "\n");
								# because of randomized string at the end - optimal treatment with a number of manual verification
								elif res.strip().startswith("PSDM : java.lang.IllegalArgumentException: Service not registered: com.google.android.gms.common.BlockingServiceConnection"):
										print "\t[+] " + line[0] + " - Success"
										success.write(line[0] + "\n");
								# because the problem is not with our code, .so lib in assets - maybe SOOT? - optimal treatment
								elif "jiagu/libjiagu_64.so" in res:
										print "\t[+] " + line[0] + " - Success"
										success.write(line[0] + "\n");									
								else:		
										#print line[0] + "\n"
										#print "Result : " + res.strip()
										if len(res.strip()) < 1:
												print "\t[+] " + line[0] + " - Success"
												success.write(line[0] + "\n");
										else:
												print "\t[-] " + line[0] + " - Verify"
												toVerify.write(line[0] + "\n");	
												#print line[0] + "\n"
												#print "Result : " + res.strip()
												#print "O1 : " + output1
												#print "O2 : " + output2
		elif line[1] == "original":
				print "We shouldn't reach here! - " + str(line)
				toVerify.write(line[0] + "\n");
				
processInfo.close();
