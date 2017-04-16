Implementation steps:

1. Copy .DLL files into C:\Windows\ADFS
	- YubicoAuthProvider.dll
	- Yubico.Library.dll

2. Add app.config sections to C:\Windows\ADFS\Microsoft.IdentityServer.Servicehost.exe.config

3. Update config with YubikeyCloud ID and Key

4. Register into AD FS using the following command:

5. Use PowerShell to register provider into AD FS 
	- $typeName = "YubicoAuthProvider.YubikeyOTP, YubicoAuthProvider, Version=1.0.0.0, Culture=neutral, PublicKeyToken=7649c32bf1339c5d"; 
	- Register-AdfsAuthenticationProvider -TypeName $typeName -Name "YubicoAuthProvider" -Verbose

6. Restart AD FS services
