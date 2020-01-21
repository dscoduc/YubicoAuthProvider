namespace Yubico.Console
{
    using System;
    using System.Configuration;
    using System.Globalization;
    using YubicoDotNetClient;

    public class Program
    {
        static string yubico_api_client_id
        { 
            get
            {
                return ConfigurationManager.AppSettings.Get("yubico_api_client_id") ?? 
                    throw new System.NullReferenceException("No Yubico Client ID found in App.config");
            }
        }

        static string yubico_api_secret_key
        {
            get
            {
                return ConfigurationManager.AppSettings.Get("yubico_api_secret_key") ?? 
                    throw new System.NullReferenceException("No Yubico API Secrey Key found in App.config");
            }
        }

        public static int Main(string[] args)
        {
            int exitCode = 0;

            try
            {
                Console.WriteLine("Press on your Yubikey to get the OTP value.  Do NOT add any quotes or other characters to the input.");
                string otp = Console.ReadLine();

                if (string.IsNullOrWhiteSpace(otp) || otp.Length == 0)
                {
                    Console.WriteLine("Unable to read Yubikey input.");
                    exitCode = -1;
                }
                else
                {
                    var client = new YubicoClient(yubico_api_client_id, yubico_api_secret_key);
                    var yubicoAnswer = client.VerifyAsync(otp).GetAwaiter().GetResult();
                    Console.WriteLine(String.Format(CultureInfo.InvariantCulture, "Validation status is : {0}.", yubicoAnswer.Status.ToString()));
                }
            }
            catch (Exception exception)
            {
                Console.WriteLine(exception.Message);
                exitCode = -2;
            }

            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
            return exitCode;
        }
    }
}
