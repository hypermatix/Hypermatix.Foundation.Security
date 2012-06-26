using System;
using Hypermatix.Foundation.Windows.API;
using System.Runtime.InteropServices;

namespace Hypermatix.Foundation.Security.Cryptography
{
    /// <summary>
    /// Description: Helper class for enhanced/wrapper cryptography functions
    /// Last Mod: 28/5/04
    /// Author: Brendan Whelan
    /// </summary>
    public class CryptographyHelper
    {
        /// <summary>
        /// Encrypt a binary array using the public key information provided in 
        /// parameter hCertContext (typically loaded from a certificate via WinCrypt API).
        /// 
        /// Notes: Uses the CryptAPI CryptEncryptMessage function to encrypted a message. 
        ///        Function assumes default 3DES/RSA encryption scheme for now (expand this later).
        /// </summary>
        public static bool EncryptMessage(byte[] bToBeEncrypted, ref byte[] EncryptedData, IntPtr hCertContext)
        {
            int EncDataSize = 0;
            int cbRecipientCertCount = 1;
            IntPtr[] recipientCert = new IntPtr[1];
            recipientCert[0] = hCertContext;

            WinCrypt.CRYPT_ENCRYPT_MESSAGE_PARA messpara = new WinCrypt.CRYPT_ENCRYPT_MESSAGE_PARA();
            WinCrypt.CRYPT_ALGORITHM_IDENTIFIER cryptAlgo = new WinCrypt.CRYPT_ALGORITHM_IDENTIFIER();
            WinCrypt.CRYPT_OBJID_BLOB objIDBlob = new WinCrypt.CRYPT_OBJID_BLOB();

            messpara.cbSize = Marshal.SizeOf(messpara);
            messpara.dwMsgEncodingType = WinCrypt.DEFAULT_ENCODING_TYPE;
            messpara.hCryptProv = 0; //Use default RSS or DSS provider
            objIDBlob.cbData = 0;
            objIDBlob.pbData = IntPtr.Zero;
            cryptAlgo.pszObjId = WinCrypt.OID_RSA_DES_EDE3_CBC;
            cryptAlgo.Parameters = objIDBlob;
            messpara.ContentEncryptionAlgorithm = cryptAlgo;
            messpara.pvEncryptionAuxInfo = IntPtr.Zero; //null
            messpara.dwFlags = 0;
            messpara.dwInnerContentType = 0;

            //First call will determine the size of the EncryptedData buffer
            if (WinCrypt.CryptEncryptMessage(ref messpara, cbRecipientCertCount, recipientCert,
                bToBeEncrypted, bToBeEncrypted.Length,
                null, ref EncDataSize))
            {
                EncryptedData = new byte[EncDataSize];
                if (!WinCrypt.CryptEncryptMessage(ref messpara, cbRecipientCertCount, recipientCert,
                    bToBeEncrypted, bToBeEncrypted.Length,
                    EncryptedData, ref EncDataSize))
                    return false;
                else
                    return true;
            }
            else
            {
                throw new Exception("WinCrypt Error: " + Win32.GetErrorMessage(Marshal.GetLastWin32Error()));
            }
        }

    }
}
