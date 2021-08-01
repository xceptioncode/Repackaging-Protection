<?php

// Change path to the location where you want to store the stats file, make sure the user has permission. Otherwise, will throw 500. 

$path = '/home/user/Documents/statsApp/';
$err = "";
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    
    if (!empty($_GET['pkgName'])) {
        $pname = $_GET['pkgName'];
        
        $json = file_get_contents('php://input');
        
        // Converts it into a PHP object
        $data = json_decode($json);
        
        $stats;
        
        $pname = preg_replace("/[^a-zA-Z0-9]/", "_", $pname);
        if (!file_exists($path . $pname)) {
            mkdir($path . $pname, 0777, true);
            $cFile = fopen($path . $pname . '/counter.ini', 'w') or die("Unable to open file!");
            fwrite($cFile, '0');
            fclose($cFile);
        }
        
        $cFile = fopen($path . $pname . '/counter.ini', 'r') or die("Unable to open file!");
        $c = fgets($cFile);
        fclose($cFile);
        
        
        $c += 1;
        $nFile = fopen($path . $pname . '/' . $c . '.json', 'w') or die("Unable to open file!");
        fwrite($nFile, $json);
        fclose($nFile);
        
        $myfile = fopen($path . $pname . '/counter.ini', "w") or die("Unable to open file!");
        fwrite($myfile, (int) $c);
        fclose($myfile);
	
	echo "Recorded successfully!";
        
    } else {
        $err .= "Package name is required!";
	echo $err;
    }
    
    
} else {
    header("HTTP/1.1 404 Not Found");
    echo "Bad request method";
    
}
?>
