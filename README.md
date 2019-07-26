# XSSwagger
Swagger-ui XSS scanner

A simple scanner that can find old versions of Swagger-ui vulnerable to various XSS attacks

#### XSS Vulnerabilities
https://snyk.io/vuln/npm:swagger-ui

#### Detecting Swagger UI version
https://github.com/swagger-api/swagger-ui/blob/master/docs/usage/version-detection.md


## Usage

```
vavkamil@localhost:~/Documents/Python/XSSwagger$ python3 xsswagger.py 
    ) (   (                                    
 ( /( )\ ))\ )                                 
 )\()|()/(()/((  (      ) (  ( (  (    (  (    
((_)\ /(_))(_))\))(  ( /( )\))()\))(  ))\ )(   
__((_|_))(_))((_)()\ )(_)|(_))((_))\ /((_|()\  
\ \/ / __/ __|(()((_|(_)_ (()(_|()(_|_))  ((_) 
 >  <\__ \__ \ V  V / _` / _` / _` |/ -_)| '_| 
/_/\_\___/___/\_/\_/\__,_\__, \__, |\___||_|   
                         |___/|___/

usage: xsswagger.py [-h] (-d DOMAIN | -D DOMAINS) [-w WORDLIST] [-t THREADS]
xsswagger.py: error: one of the arguments -d -D is required
```

## Example

```
vavkamil@localhost:~/Documents/Python/XSSwagger$ python3 xsswagger.py -D test.txt
    ) (   (                                    
 ( /( )\ ))\ )                                 
 )\()|()/(()/((  (      ) (  ( (  (    (  (    
((_)\ /(_))(_))\))(  ( /( )\))()\))(  ))\ )(   
__((_|_))(_))((_)()\ )(_)|(_))((_))\ /((_|()\  
\ \/ / __/ __|(()((_|(_)_ (()(_|()(_|_))  ((_) 
 >  <\__ \__ \ V  V / _` / _` / _` |/ -_)| '_| 
/_/\_\___/___/\_/\_/\__,_\__, \__, |\___||_|   
                         |___/|___/

[i] Scanning multiple domains: test.txt
[i] Domains in a list: 5

****************************************************************************************************
****************************************************************************************************

[ Redirect ] https://dev.fitbit.com/build/reference/web-api/explore -> https://dev.fitbit.com/build/reference/web-api/explore/
[ 200 ] [ Swagger UI ] https://dev.fitbit.com/build/reference/web-api/explore/
[ Version ] 3.19.2 detected!

[ Vulnerable ] version 3.19.2 detected!
----------------------------------------------------------------------------------------------------
[ Severity ] Medium
[ Vulnerable ] <3.20.9
[ Published ] 14 Jun, 2019
[ Vulnerability ] Cross-site Scripting (XSS)
[ Detail ] https://snyk.io/vuln/SNYK-JS-SWAGGERUI-449921

****************************************************************************************************
****************************************************************************************************

[ 200 ] [ API Documentation ] https://promo-services-staging.brave.com/documentation
[ Version ] 2.1.4 detected!

[ Vulnerable ] version 2.1.4 detected!
----------------------------------------------------------------------------------------------------
[ Severity ] High
[ Vulnerable ] <2.2.1
[ Published ] 25 Jul, 2016
[ Vulnerability ] Cross-site Scripting (XSS)
[ Detail ] https://snyk.io/vuln/npm:swagger-ui:20160725
----------------------------------------------------------------------------------------------------
[ Severity ] Medium
[ Vulnerable ] <2.2.3
[ Published ] 13 Mar, 2017
[ Vulnerability ] Cross-site Scripting (XSS)
[ Detail ] https://snyk.io/vuln/npm:swagger-ui:20160901
----------------------------------------------------------------------------------------------------
[ Severity ] Medium
[ Vulnerable ] >=3.0.0 <3.0.13
[ Published ] 16 Jun, 2019
[ Vulnerability ] Cross-site Scripting (XSS)
[ Detail ] https://snyk.io/vuln/SNYK-JS-SWAGGERUI-449941
----------------------------------------------------------------------------------------------------
[ Severity ] Medium
[ Vulnerable ] <3.4.2
[ Published ] 25 Dec, 2017
[ Vulnerability ] Cross-site Scripting (XSS)
[ Detail ] https://snyk.io/vuln/npm:swagger-ui:20171031
----------------------------------------------------------------------------------------------------
[ Severity ] Medium
[ Vulnerable ] <3.18.0
[ Published ] 13 Jun, 2019
[ Vulnerability ] Reverse Tabnabbing
[ Detail ] https://snyk.io/vuln/SNYK-JS-SWAGGERUI-449808
----------------------------------------------------------------------------------------------------
[ Severity ] Medium
[ Vulnerable ] <3.20.9
[ Published ] 14 Jun, 2019
[ Vulnerability ] Cross-site Scripting (XSS)
[ Detail ] https://snyk.io/vuln/SNYK-JS-SWAGGERUI-449921

****************************************************************************************************
****************************************************************************************************

[ 200 ] [ Swagger UI ] https://api.hitbtc.com/api/2/explore/
[ Version ] 3.19.5 detected!

[ Vulnerable ] version 3.19.5 detected!
----------------------------------------------------------------------------------------------------
[ Severity ] Medium
[ Vulnerable ] <3.20.9
[ Published ] 14 Jun, 2019
[ Vulnerability ] Cross-site Scripting (XSS)
[ Detail ] https://snyk.io/vuln/SNYK-JS-SWAGGERUI-449921

****************************************************************************************************
****************************************************************************************************

[ 200 ] [ Swagger UI ] https://console.cloud.vmware.com/csp/gateway/slc/api/swagger-ui.html
[ Version ] Idk, please check manually!

[ Done ] Don't be evil!


```
