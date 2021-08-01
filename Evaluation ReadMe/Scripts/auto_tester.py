import subprocess, sys,  os, time
from threading import Thread

"""

This script was used to automatically embed repackaging detection capability into the android apps, collect extended information, event screenshots & logs, perform UI guided testing using droidbot for both protected version of the application generated using our system and original application, etc.

"""

if (len(sys.argv) < 2 or len(sys.argv) > 2):
        print("""\nThis script run test and saves screenshot, logcat, build.log, etc.\n\n Usage: %s appsDir \n\n Example: %s apps/\n""" %(sys.argv[0], sys.argv[0]));
        exit();

stats = open("collected_auto_test.txt", "a");
error = open("error_auto_test.txt", "a");
timetaken = open("running_time_droid.txt", "a");
error1 = open("error_transform.txt", "a");
processInfo = open("processInfo.txt", "a");
sizeChart = open("sizeChart.txt", "a");

transformMax = "cd /home/user/Gitlab/rajs_repackaging_analysis/RepackagingProtection && ant clean transform-and-install-apk -Dexport=yes -Dsrc-apk=";
dir = sys.argv[1];
test_count = 0;

# Used to record PID 

def findPID(p, status):
		time.sleep(5);
		#print p
		output = subprocess.check_output(['bash', '-c', './PID_finder.sh ' + p]);
		if output == "\n":
				findPID(p, status);
		else:
				#print output
				processInfo.write(p.split("/")[-1] + "----" + status + "----" + str(output));

# Used to record memory info 

def saveMemInfo(p, status, path):
		time.sleep(5);
		path = path;
		#print p
		output = subprocess.check_output(['bash', '-c', './getMemInfo.sh ' + p]);
		if output.startswith("No process found for"):
				saveMemInfo(p, status, path);
		else:
				for i in range(0, 3):
						#print output
						#processInfo.write(p.split("/")[-1] + "----" + status + "----" + str(output));
						meminfo = open("meminfo_" + str(i) + ".log", "w");
						meminfo.write(output);
						meminfo.close()
						copy_info = subprocess.check_output(['bash', '-c', 'cd /home/user/Gitlab/rajs_repackaging_analysis/RepackagingProtection/stats/performance_screen_test && cp meminfo_' + str(i) + '.log ' + path]);
						time.sleep(10);

print "Collected stats for: "
for root, dirs, files in os.walk(dir):
        for f in files:
                if f.endswith(".apk"):
			try:
				folder = f.replace(" ", "_").replace(".", "_").replace("/", '') + "_transformed";
				if not os.path.exists("/home/user/Gitlab/rajs_repackaging_analysis/RepackagingProtection/stats/performance_screen_test/data/" + folder):
					os.mkdir("/home/user/Gitlab/rajs_repackaging_analysis/RepackagingProtection/stats/performance_screen_test/data/" + folder);
				else:
					continue
				#dir = subprocess.check_output(['bash', '-c', 'cd /home/user/Gitlab/rajs_repackaging_analysis/RepackagingProtection/stats/auto_screenshot_testing/data && mkdir ', folder]);
				# Maximized Transformation
				transformer = transformMax + "'" + dir + f + "' > build.log";
				folder_path = "'/home/user/Gitlab/rajs_repackaging_analysis/RepackagingProtection/stats/performance_screen_test/data/" + folder + "'";
				#print transformer + "\n";
				print "\n[!] " + str(test_count) + ". Working on -- " + f
				test_count += 1
				try:
					output = subprocess.check_output(['bash', '-c', transformer]);
					print "\t[+] Transformed - " + f;
				except Exception as e:
					print "\t[-] Error Transforming - " + f;
					copy_log = subprocess.check_output(['bash', '-c', 'cd /home/user/Gitlab/rajs_repackaging_analysis/RepackagingProtection && cp build.log ' + folder_path]);
					error1.write(str(f) + "\n");
					continue
				#DroidBot
				droid = "droidbot -a '/home/user/Gitlab/rajs_repackaging_analysis/RepackagingProtection/sootOutput/" + f + "' -count 25 -grant_perm -ignore_ad -keep_env -interval 2 -o " + folder_path + " &> droid_transformed_output";
				start = time.time();
				Thread(target = findPID, args=[dir+f, "transformed"]).start()
				Thread(target = saveMemInfo, args=[dir+f, "transformed", folder_path]).start()
				output = subprocess.check_output(['bash', '-c', droid])
				end = time.time();
				timetaken.write(folder + "__" + str(end-start));
				
				copy_log = subprocess.check_output(['bash', '-c', 'cd /home/user/Gitlab/rajs_repackaging_analysis/RepackagingProtection && cp build.log ' + folder_path]);
				copy_botLog = subprocess.check_output(['bash', '-c', 'cd /home/user/Gitlab/rajs_repackaging_analysis/RepackagingProtection/stats/performance_screen_test/ && cp droid_transformed_output ' + folder_path]);
				
				size_transformed_cmd = "du --block-size=1K '/home/user/Gitlab/rajs_repackaging_analysis/RepackagingProtection/sootOutput/" + f + "' | cut -d '/' -f 1"
				size_transformed = subprocess.check_output(['bash', '-c', size_transformed_cmd]);
				
				sizeChart.write(str(f) + "----" + size_transformed.replace("\n", "----"));
				
				print "\t\t[+] Transformed tested - " + f;


				# Original
				folder = f.replace(" ", "_").replace(".", "_").replace("/", '') + "_original";
				if not os.path.exists("/home/user/Gitlab/rajs_repackaging_analysis/RepackagingProtection/stats/performance_screen_test/data/" + folder):
					os.mkdir("/home/user/Gitlab/rajs_repackaging_analysis/RepackagingProtection/stats/performance_screen_test/data/" + folder);
				else:
					continue
				folder_path = "'/home/user/Gitlab/rajs_repackaging_analysis/RepackagingProtection/stats/performance_screen_test/data/" + folder + "'";
				#DroidBot
				droid = "droidbot -a '" + dir + f + "' -count 25 -grant_perm -ignore_ad -keep_env -interval 2 -o " + folder_path + " &> droid_original_output";
				start = time.time()
				Thread(target = findPID, args=[dir+f, "original"]).start()
				Thread(target = saveMemInfo, args=[dir+f, "original", folder_path]).start()
				output = subprocess.check_output(['bash', '-c', droid])
				copy_botLog = subprocess.check_output(['bash', '-c', 'cd /home/user/Gitlab/rajs_repackaging_analysis/RepackagingProtection/stats/performance_screen_test/ && cp droid_original_output ' + folder_path]);
				
				size_original_cmd = "du --block-size=1K " + dir + f + " | cut -d '/' -f 1"
				size_original = subprocess.check_output(['bash', '-c', size_original_cmd]);
				
				sizeChart.write(size_original);
				
				end = time.time()
				timetaken.write("__" + str(end-start) + "\n");
				print "\t[+] Original tested - " + f + "\n";
		                stats.write(str(f) + "\n");
			except KeyboardInterrupt:
				print "Ctrl+c pressed, closing ..";
				stats.close();
				error.close();
				error1.close();
				timetaken.close();
				processInfo.close();
				sizeChart.close();
				break;
			except Exception as e:
				print  "\t\t[-] Failed - " + f + " - " + str(e) 
				error.write(str(f) + "\n");
				pass
	break

stats.close();
error.close();
error1.close();
timetaken.close();
processInfo.close();
sizeChart.close();
