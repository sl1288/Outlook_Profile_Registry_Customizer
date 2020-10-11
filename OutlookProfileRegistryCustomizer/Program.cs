using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using IniParser;
using IniParser.Model;

namespace OutlookProfileRegistryCustomizer
{
    class Program
    {
       

        public static void CopyFilesRecursively(DirectoryInfo source, DirectoryInfo target)
        {
            foreach (DirectoryInfo dir in source.GetDirectories())
                CopyFilesRecursively(dir, target.CreateSubdirectory(dir.Name));
            foreach (FileInfo file in source.GetFiles())
                file.CopyTo(Path.Combine(target.FullName, file.Name),true);
        }

        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                .ToArray();
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct DATA_BLOB
        {
            public int cbData;
            public IntPtr pbData;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct CRYPTPROTECT_PROMPTSTRUCT
        {
            public int cbSize;
            public int dwPromptFlags;
            public IntPtr hwndApp;
            public string szPrompt;
        }

        [Flags]
        private enum CryptProtectFlags
        {
            // for remote-access situations where ui is not an option
            // if UI was specified on protect or unprotect operation, the call
            // will fail and GetLastError() will indicate ERROR_PASSWORD_RESTRICTION
            CRYPTPROTECT_UI_FORBIDDEN = 0x1,

            // per machine protected data -- any user on machine where CryptProtectData
            // took place may CryptUnprotectData
            CRYPTPROTECT_LOCAL_MACHINE = 0x4,

            // force credential synchronize during CryptProtectData()
            // Synchronize is only operation that occurs during this operation
            CRYPTPROTECT_CRED_SYNC = 0x8,

            // Generate an Audit on protect and unprotect operations
            CRYPTPROTECT_AUDIT = 0x10,

            // Protect data with a non-recoverable key
            CRYPTPROTECT_NO_RECOVERY = 0x20,


            // Verify the protection of a protected blob
            CRYPTPROTECT_VERIFY_PROTECTION = 0x40
        }

        // Wrapper for DPAPI CryptProtectData function.
        [DllImport("Crypt32.dll",SetLastError = true,CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptProtectData(
            ref DATA_BLOB pDataIn,
            String szDataDescr,
            ref DATA_BLOB pOptionalEntropy,
            IntPtr pvReserved,
            ref CRYPTPROTECT_PROMPTSTRUCT pPromptStruct,
            CryptProtectFlags dwFlags,
            ref DATA_BLOB pDataOut
        );


        [DllImport("Crypt32.dll",SetLastError = true,CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptUnprotectData(
            ref DATA_BLOB pDataIn,
            StringBuilder szDataDescr,
            ref DATA_BLOB pOptionalEntropy,
            IntPtr pvReserved,
            ref CRYPTPROTECT_PROMPTSTRUCT pPromptStruct,
            CryptProtectFlags dwFlags,
            ref DATA_BLOB pDataOut
        );


        private static void InitBLOB(byte[] data, ref DATA_BLOB blob)
        {
            // Use empty array for null parameter.
            if (data == null)
                data = new byte[0];

            // Allocate memory for the BLOB data.
            blob.pbData = Marshal.AllocHGlobal(data.Length);

            // Make sure that memory allocation was successful.
            if (blob.pbData.Equals(IntPtr.Zero))
                throw new Exception("Unable to allocate data buffer for BLOB structure.");

            // Specify number of bytes in the BLOB.
            blob.cbData = data.Length-1;
            Marshal.Copy(data, 1, blob.pbData, data.Length-1);
        }

        static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("mode mode-params");
                Console.WriteLine("display in-file");
                Console.WriteLine("modify in-file out-file config-file");
                return;
            }

            Regex splitRegex = new Regex("\"(.+)\"=hex:(.+)", RegexOptions.Compiled);

            if (args[0] == "display")
            {
                var data = File.ReadAllLines(args[1]);
                foreach (var line in data)
                {
                    if (line.Contains("=hex:"))
                    {
                        MatchCollection matches = splitRegex.Matches(line);
                        if (matches.Count > 0)
                        {
                            var variable = matches[0].Groups[1].Value;
                            var hexString = matches[0].Groups[2].Value;
                            hexString = hexString.Replace(",", "");
                            var bytes = StringToByteArray(hexString);
                            var utf8String = Encoding.Unicode.GetString(bytes);
                            Console.WriteLine("Var:" + variable + " String:" + utf8String);
                        }
                    }
                }
            }

            if (args[0] == "dumppw")
            {

                RegistryKey pRegKey = Registry.CurrentUser;

                pRegKey = pRegKey.OpenSubKey(args[1]);
                byte[] regvalue = (byte[]) pRegKey.GetValue("EAS Password");

                DATA_BLOB OutlookBlob = new DATA_BLOB();
                DATA_BLOB PasswordBlob = new DATA_BLOB();
                DATA_BLOB EntropyBlob = new DATA_BLOB();
                EntropyBlob.cbData = 0;
                EntropyBlob.pbData = Marshal.AllocHGlobal(0);

                StringBuilder ODescription = null;
                System.IntPtr OReserved = default(IntPtr);
                CRYPTPROTECT_PROMPTSTRUCT OPrompt = default(CRYPTPROTECT_PROMPTSTRUCT);

                InitBLOB(regvalue, ref OutlookBlob);

                if (CryptUnprotectData(ref OutlookBlob, ODescription, ref EntropyBlob, OReserved, ref OPrompt,
                    CryptProtectFlags.CRYPTPROTECT_UI_FORBIDDEN, ref PasswordBlob))
                {
                    Console.WriteLine("CryptUnprotectData OK");
                    Console.WriteLine(PasswordBlob.cbData);

                    byte[] managedArray = new byte[PasswordBlob.cbData];
                    Marshal.Copy(PasswordBlob.pbData, managedArray, 0, PasswordBlob.cbData);

                    string hexString = BitConverter.ToString(managedArray).ToLowerInvariant().Replace('-', ',');
                    Console.WriteLine(hexString);

                    string pw = Marshal.PtrToStringAuto(PasswordBlob.pbData);
                    Console.WriteLine(pw.Length);
                    Console.WriteLine("'" + pw + "'");
                }
                else
                {
                    Console.WriteLine("CryptUnprotectData ERROR");
                }
            }


            // #######################################################################################
             
            if (args[0] == "modify")
            {
                var data = File.ReadAllLines(args[1]);
                using (var outputFile = new StreamWriter(args[2], false, Encoding.Unicode))
                {
                    var parser = new FileIniDataParser();
                    var configReader = new MemoryStream(System.Convert.FromBase64String(File.ReadAllText(args[3], Encoding.ASCII)));
                    IniData config = parser.ReadData(new StreamReader(configReader, Encoding.UTF8, true));

                    config["newprofile"]["path"] = Path.GetFullPath(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                        @"..\Local\Microsoft\Outlook\" + config["newprofile"]["email"] + ".ost"));

                    foreach (var line in data)
                    {
                        var curLine = line;
                        if (curLine.Contains("=hex:") && !curLine.Contains("\"EAS Password\""))
                        {
                            var oldProfileEmail =
                                BitConverter.ToString(Encoding.Unicode.GetBytes(config["oldprofile"]["email"])).ToLowerInvariant().Replace('-', ',');
                            var oldProfilePath =
                                BitConverter.ToString(Encoding.Unicode.GetBytes(config["oldprofile"]["path"])).ToLowerInvariant().Replace('-', ',');
                            var newProfileEmail =
                                BitConverter.ToString(Encoding.Unicode.GetBytes(config["newprofile"]["email"])).ToLowerInvariant().Replace('-', ',');
                            var newProfilePath =
                                BitConverter.ToString(Encoding.Unicode.GetBytes(config["newprofile"]["path"])).ToLowerInvariant().Replace('-', ',');

                            if (curLine.Contains(oldProfilePath))
                            {
                                curLine = curLine.Replace(oldProfilePath, newProfilePath);
                            }
                            else if (curLine.Contains(oldProfileEmail))
                            {
                                curLine = curLine.Replace(oldProfileEmail, newProfileEmail);
                            }
                        
                            outputFile.WriteLine(curLine);
                        }
                        else
                        {
                            if (line.StartsWith("\"Account Name\"=\"" + config["oldprofile"]["email"] + "\""))
                            {
                                outputFile.WriteLine("\"Account Name\"=\"" + config["newprofile"]["email"] + "\"");
                            }
                            else if (line.StartsWith("\"Display Name\"=\""))
                            {
                                outputFile.WriteLine("\"Display Name\"=\"" + config["newprofile"]["name"] + "\"");
                            }
                            else if (line.StartsWith("\"Email\"=\""))
                            {
                                outputFile.WriteLine("\"Email\"=\"" + config["newprofile"]["email"] + "\"");
                            }
                            else if (line.StartsWith("\"EAS Server URL\"=\""))
                            {
                                outputFile.WriteLine("\"EAS Server URL\"=\"" + config["newprofile"]["server"] + "\"");
                            }
                            else if (line.StartsWith("\"EAS User\"=\""))
                            {
                                outputFile.WriteLine("\"EAS User\"=\"" + config["newprofile"]["user"] + "\"");
                            }
                            else if (line.StartsWith("\"EAS Password\"="))
                            {
                                var newPwByte = Encoding.Unicode.GetBytes(config["newprofile"]["pass"] + "\0");

                                DATA_BLOB newPwDataBlob = new DATA_BLOB();
                                newPwDataBlob.cbData = newPwByte.Length;
                                newPwDataBlob.pbData = Marshal.AllocHGlobal(newPwByte.Length + 1);
                                Marshal.Copy(newPwByte, 0, newPwDataBlob.pbData, newPwByte.Length);

                                DATA_BLOB newEntropyBlob = new DATA_BLOB();
                                newEntropyBlob.cbData = 0;
                                newEntropyBlob.pbData = Marshal.AllocHGlobal(0);

                                CRYPTPROTECT_PROMPTSTRUCT newOPrompt = default(CRYPTPROTECT_PROMPTSTRUCT);

                                DATA_BLOB newEncDataBlob = new DATA_BLOB();

                                if (CryptProtectData(ref newPwDataBlob, null, ref newEntropyBlob, default(IntPtr), ref newOPrompt,
                                    CryptProtectFlags.CRYPTPROTECT_UI_FORBIDDEN, ref newEncDataBlob))
                                {
                                    byte[] managedArray = new byte[newEncDataBlob.cbData];
                                    Marshal.Copy(newEncDataBlob.pbData, managedArray, 0, newEncDataBlob.cbData);

                                    string hexString = "02," + BitConverter.ToString(managedArray).ToLowerInvariant().Replace('-', ',');
                                    outputFile.WriteLine("\"EAS Password\"=hex:" + hexString);
                                }
                                else
                                {
                                    Console.WriteLine("enc err");
                                }
                            }
                            else
                            {
                                outputFile.WriteLine(curLine);
                            }
                        }
                    }
                }
            }

            if (args[0] == "signature")
            {
                var srcFolder = Path.GetFullPath(args[1]);
                var destFolder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    @"Microsoft\Signatures\");
                if (!Directory.Exists(destFolder))
                {
                    Directory.CreateDirectory(destFolder);
                }

                CopyFilesRecursively(new DirectoryInfo(srcFolder), new DirectoryInfo(destFolder));

                var parser = new FileIniDataParser();
                var configReader = new MemoryStream(System.Convert.FromBase64String(File.ReadAllText(args[2], Encoding.ASCII)));
                IniData config = parser.ReadData(new StreamReader(configReader,Encoding.UTF8,true));

                foreach (var file in Directory.GetFiles(srcFolder))
                {
                    if (file.EndsWith(".txt") || file.EndsWith(".htm") || file.EndsWith(".rtf"))
                    {
                        Encoding usedEncoding = null;
                        if (file.EndsWith(".txt"))
                        {
                            usedEncoding = Encoding.Unicode;
                        }
                        if (file.EndsWith(".htm"))
                        {
                            usedEncoding = Encoding.GetEncoding(1252);
                        }
                        if (file.EndsWith(".rtf"))
                        {
                            usedEncoding = new UTF8Encoding(false);
                        }


                        string data = File.ReadAllText(file, usedEncoding);
                        foreach (KeyData keyData in config["newprofile"])
                        {
                            data = data.Replace("##" + keyData.KeyName.ToUpperInvariant() + "##", keyData.Value);
                        }

                        var targetFile = file.Replace(srcFolder, destFolder);
                        File.WriteAllText(targetFile, data, usedEncoding);
                        
                    }
                }
            }


        }
    }
}
