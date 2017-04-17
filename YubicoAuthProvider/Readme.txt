Implementation steps:

1. Copy project .DLL files into C:\Windows\ADFS
	- YubicoAuthProvider.dll
	- Yubico.Library.dll

2. Add config sections into C:\Windows\ADFS\Microsoft.IdentityServer.Servicehost.exe.config
	(settings can be found in app.config file of this project)

3. Update YubicoCredentials setting in config with YubikeyCloud ID and Key
	(ex. Id="12345" PrivateKey="gobblygookgobblygook")

4. Update AppSettings setting with AD attribute that will be holding Yubikey Token IDs for users
	(ex. key="yubikeytokenidattributefield" value="departmentNumber")

5. Use PowerShell to register provider into AD FS 
	- $typeName = "YubicoAuthProvider.YubikeyOTP, YubicoAuthProvider, Version=1.0.0.0, Culture=neutral, PublicKeyToken=7649c32bf1339c5d"; 
	- Register-AdfsAuthenticationProvider -TypeName $typeName -Name "YubicoAuthProvider" -Verbose

6. Restart AD FS services

7. Populate AD user object attribute specified in the yubikeytokenidattributefield key
	(ex. departmentNumber ["tokenid1","tokenid2"])