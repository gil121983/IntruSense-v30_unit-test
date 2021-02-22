	# IntruSense-v30 Unit Test
      ------------------------------


This repository contains maliciuos files for testing reasons, 
make sure the files are deleted after testing.


# Testing Secopx Sensor

Start tests by runnung: 
	
	$ sensor_test --<FEATURE_NAME>  -<OPTION>

To tests all features add:	
	
			--all 		

Or selective tests by adding options:

			--chkrootkit
			--yara
			--webshells
			--coinscan
			--predictor
			--btmp
			--scalp
			--dos
			--cve
			--outdated

You must add one of the options:

			-c 	To creaet test	

			-d	To delete test
