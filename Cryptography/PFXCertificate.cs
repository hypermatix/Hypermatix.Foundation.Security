using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Hypermatix.Foundation.Windows.API;
using System.Diagnostics;

namespace Hypermatix.Foundation.Security.Cryptography
{
    /// <summary>
    /// Description: Class for usage of Personal Information Exchange (PFX) format
	///              certificate file (typically .p12 file)
    /// Last Mod: 28/5/04
    /// Author: Brendan Whelan
    /// </summary>
    public class PFXCertificate
    {
        #region Types
        String[] CSPTypes = {
								null,
								"PROV_RSA_FULL",	//1
								"PROV_RSA_SIG",	//2
								"PROV_DSS",
								"PROV_FORTEZZA",
								"PROV_MS_EXCHANGE",
								"PROV_SSL",
								null, null, null, null, null,
								"PROV_RSA_SCHANNEL",	//12
								"PROV_DSS_DH",
								"PROV_EC_ECDSA_SIG",
								"PROV_EC_ECNRA_SIG",
								"PROV_EC_ECDSA_FULL",
								"PROV_EC_ECNRA_FULL",
								"PROV_DH_SCHANNEL",
								null,
								"PROV_SPYRUS_LYNKS",	//20
								"PROV_RNG",
								"PROV_INTEL_SEC",
								"PROV_REPLACE_OWF",
								"PROV_RSA_AES"		// 24
							};
        String[] keyspecs = { null, "AT_KEYEXCHANGE", "AT_SIGNATURE" };
#endregion

        #region Private Variables
        private X509Certificate pfxcert;
        private String pfxcontainer;
        private String pfxprovname;
        private uint pfxprovtype;
        private uint pfxkeyspec;
        private uint pfxcertkeysize;
        private byte[] pfxcertkeyexponent;
        private byte[] pfxcertkeymodulus;
        private IntPtr hCertCntxt = IntPtr.Zero;
        private IntPtr hMemStore = IntPtr.Zero;
        private IntPtr pProvInfo = IntPtr.Zero;
        #endregion

        #region Public Properties
        public X509Certificate Certificate
        {
            get { return pfxcert; }
        }
        public uint KeySize
        {
            get { return pfxcertkeysize; }
        }
        public byte[] KeyExponent
        {
            get { return pfxcertkeyexponent; }
        }
        public byte[] KeyModulus
        {
            get { return pfxcertkeymodulus; }
        }
        #endregion

        #region Public methods
        /// <summary>
        /// Load PFX file
        /// Note: Uses first key container in file as source for class variables.
        ///       There could be more than one container - this should be extended to
        ///       allow caller to note this, ask user if necessary, and supply which container to use.
        /// </summary>
        public bool LoadPfx(String pfxfilename, ref String pswd)
        {
            if (pProvInfo != IntPtr.Zero)
                Marshal.FreeHGlobal(pProvInfo);
            if (hCertCntxt != IntPtr.Zero)
                try
                {
                    WinCrypt.CertFreeCertificateContext(hCertCntxt);
                }
                catch (Exception e) { }
            if (hMemStore != IntPtr.Zero)
                WinCrypt.CertCloseStore(hMemStore, 0);

            uint provinfosize = 0;
            bool result = false;

            if (!File.Exists(pfxfilename))
            {
                Debug.Fail("File '{0}' not found.", pfxfilename);
                return result;
            }

            byte[] pfxdata = PFXCertificate.GetFileBytes(pfxfilename);
            if (pfxdata == null || pfxdata.Length == 0)
                return result;

            //Initialize struct and allocate memory for pfx data
            WinCrypt.CRYPT_DATA_BLOB ppfx = new WinCrypt.CRYPT_DATA_BLOB();
            ppfx.cbData = pfxdata.Length;
            ppfx.pbData = Marshal.AllocHGlobal(pfxdata.Length);
            Marshal.Copy(pfxdata, 0, ppfx.pbData, pfxdata.Length);

            if (!WinCrypt.PFXIsPFXBlob(ref ppfx))
            {
                Debug.Fail("File '{0}' is not a valid pfx file", pfxfilename);
                return result;
            }

            //Import pfx into memory store
            hMemStore = WinCrypt.PFXImportCertStore(ref ppfx, pswd, WinCrypt.CRYPT_USER_KEYSET);
            pswd = null;
            if (hMemStore == IntPtr.Zero)
            {
                string errormessage = new Exception("Win32 Error:" + Marshal.GetLastWin32Error()).Message;
                Console.WriteLine("\n{0}", errormessage);
                Marshal.FreeHGlobal(ppfx.pbData);
                return result;
            }
            Marshal.FreeHGlobal(ppfx.pbData);

            //Iterate loaded cert store and return first cert with private key container
            //TODO:  May be several 
            while ((hCertCntxt = WinCrypt.CertEnumCertificatesInStore(hMemStore, hCertCntxt)) != IntPtr.Zero)
            {
                if (WinCrypt.CertGetCertificateContextProperty(hCertCntxt, WinCrypt.CERT_KEY_PROV_INFO_PROP_ID, IntPtr.Zero, ref provinfosize))
                    pProvInfo = Marshal.AllocHGlobal((int)provinfosize);
                else
                    continue;
                if (WinCrypt.CertGetCertificateContextProperty(hCertCntxt, WinCrypt.CERT_KEY_PROV_INFO_PROP_ID, pProvInfo, ref provinfosize))
                {
                    WinCrypt.CRYPT_KEY_PROV_INFO ckinfo = (WinCrypt.CRYPT_KEY_PROV_INFO)Marshal.PtrToStructure(pProvInfo, typeof(WinCrypt.CRYPT_KEY_PROV_INFO));
                    Marshal.FreeHGlobal(pProvInfo);

                    this.pfxcontainer = ckinfo.ContainerName;
                    this.pfxprovname = ckinfo.ProvName;
                    this.pfxprovtype = ckinfo.ProvType;
                    this.pfxkeyspec = ckinfo.KeySpec;
                    this.pfxcert = new X509Certificate(hCertCntxt);
                    if (!this.GetCertPublicKey(pfxcert))
                        Debug.Write("Couldn't get certificate public key");
                    result = true;
                    break;
                }
            }

            return result;
        }


        public override string ToString()
        {
            string about = String.Format(
                "ContainerName:\t{0}\nProviderName:\t{1}\nProvType: {2}\t({3}) \nKeySpec:  {4}\t({5})\n{6}Keysize:\t{7} bits",
                this.pfxcontainer,
                this.pfxprovname,
                this.pfxprovtype, CSPTypes[this.pfxprovtype],
                this.pfxkeyspec, keyspecs[this.pfxkeyspec],
                this.pfxcert.ToString(true),
                this.pfxcertkeysize);
            return about;
        }

        #endregion

        #region Private Methods
        private bool GetCertPublicKey(X509Certificate cert)
        {
            byte[] publickeyblob;
            byte[] encodedpubkey = cert.GetPublicKey(); 

            uint blobbytes = 0;
            if (WinCrypt.CryptDecodeObject(WinCrypt.DEFAULT_ENCODING_TYPE, WinCrypt.RSA_CSP_PUBLICKEYBLOB, encodedpubkey, (uint)encodedpubkey.Length, 0, null, ref blobbytes))
            {
                publickeyblob = new byte[blobbytes];
                WinCrypt.CryptDecodeObject(WinCrypt.DEFAULT_ENCODING_TYPE, WinCrypt.RSA_CSP_PUBLICKEYBLOB, encodedpubkey, (uint)encodedpubkey.Length, 0, publickeyblob, ref blobbytes);
            }
            else
                return false;

            WinCrypt.PUBKEYBLOBHEADERS pkheaders = new WinCrypt.PUBKEYBLOBHEADERS();
            int headerslength = Marshal.SizeOf(pkheaders);
            IntPtr buffer = Marshal.AllocHGlobal(headerslength);
            Marshal.Copy(publickeyblob, 0, buffer, headerslength);
            pkheaders = (WinCrypt.PUBKEYBLOBHEADERS)Marshal.PtrToStructure(buffer, typeof(WinCrypt.PUBKEYBLOBHEADERS));
            Marshal.FreeHGlobal(buffer);
            //Get public key size (bits)
            this.pfxcertkeysize = pkheaders.bitlen;

            //Public exponent
            byte[] exponent = BitConverter.GetBytes(pkheaders.pubexp); //little-endian ordered
            Array.Reverse(exponent);    //convert to big-endian order
            this.pfxcertkeyexponent = exponent;

            //Modulus
            int modulusbytes = (int)pkheaders.bitlen / 8;
            byte[] modulus = new byte[modulusbytes];
            try
            {
                Array.Copy(publickeyblob, headerslength, modulus, 0, modulusbytes);
                Array.Reverse(modulus);   //convert from little to big-endian ordering.
                this.pfxcertkeymodulus = modulus;
            }
            catch (Exception)
            {
                Debug.Fail("Problem getting modulus from publickeyblob");
                return false;
            }
            return true;
        }

        private static byte[] GetFileBytes(String filename)
        {
            if (!File.Exists(filename))
                return null;
            Stream stream = new FileStream(filename, FileMode.Open);
            byte[] filebytes = null;
            try
            {
                int datalen = (int)stream.Length;
                filebytes = new byte[datalen];
                stream.Seek(0, SeekOrigin.Begin);
                stream.Read(filebytes, 0, datalen);
            }
            finally
            {
                stream.Close();
            }
            return filebytes;
        }
        #endregion

        ~PFXCertificate()
        {
            //Always clean-up unmanaged resources
            if (pProvInfo != IntPtr.Zero)
                Marshal.FreeHGlobal(pProvInfo);
            if (hCertCntxt != IntPtr.Zero)
                try
                {
                    WinCrypt.CertFreeCertificateContext(hCertCntxt);
                }
                catch (Exception e) { }
            if (hMemStore != IntPtr.Zero)
                WinCrypt.CertCloseStore(hMemStore, 0);
        }
    }
}
