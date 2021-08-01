import subprocess, sys,  os
from PIL import Image
import imagehash
import glob
from diffimg import diff

"""
This was used to automatically compare event screenshots of original and protected version of the applicaton using perceptual hashing in order to ensure that UI was not distorted as result of adding repackaging detection capability. This also helped us to find if any original application contained any kind of repackaging detection capability & response. 

Due to the nature of perceptual hashing & possibility of dynamic resources, screenshots were also manually compared later on to formalize accurate results.

"""


if (len(sys.argv) < 2 or len(sys.argv) > 2):
        print("""\nThis script run test to compare screenshots and find unique items.\n\n Usage: %s packageDir \n\n Example: %s org_mozilla_rocket/\n""" %(sys.argv[0], sys.argv[0]));
        exit();

dir = sys.argv[1];
toVerify = open("verify_these_screenshot.txt", "a");
success = open("successful_test_screenshot.txt", "a");

print "Running comparison test: "
for root, dirs, files in os.walk(dir):
        for d in dirs:
                if d.endswith("_transformed"):
						if ((not os.path.exists(dir + d)) or (not os.path.exists(dir + d.replace("_transformed", "_original")))):
								continue;
						d_name = d.replace("_transformed", '')
						print "  [+] Testing - " + d_name
						try:
								list_image = [ ]
								list_image_hash = { }
								list_image.extend(glob.glob(dir + d + "/states/*.jpg"))
								len_transformed = len(list_image)
								list_image.extend(glob.glob(dir + d.replace("_transformed", '') + "_original" + "/states/*.jpg"))
								len_original = len(list_image) - len_transformed
								print "\n      [!] We should have a maximum of [" + str(len_original-len_transformed).strip("-") + "] unique hash(es) left!"
								#print list_image
								for i in list_image:
										hash = imagehash.average_hash(Image.open(i))
										#print str(hash) + "-" + str(i)
										#casting to STR is required
										if str(hash) in list_image_hash:
												#print hash
												del list_image_hash[(str(hash))]
										else:
												#list_image_hash.append(str(hash))
												list_image_hash[(str(hash))] = i
								if len(list_image_hash) == 0: 
										print "\n      [+] No hashes left. Success!\n"
										success.write(d_name + "\n");
								if len(list_image_hash) > 0:
										if len(list_image_hash) == int(str(len_original-len_transformed).strip("-")): 
												print "\n      [!] Found these unique items (SUCCESS): "
												success.write(d_name + "\n");
										else:
												print "\n      [!] Found these unique items (VERIFY): "
												toVerify.write(d_name + "\n")
										for i in list_image_hash:
												print "\n\t" +i + "    " + list_image_hash[i]
						except Exception as e:
								print "  [-] Error testing - " + d_name + " - " + str(e)
						
print "\n"
toVerify.close();
success.close();
