package samples;

import tss.Tpm;
import tss.TpmFactory;
import tss.tpm.*;

public class sample {
   private boolean usesTbs;
   private Tpm tpm;
   private TPMT_PUBLIC aesTemplate;

   private byte[][] iv;


   private  byte[] aesKey;


    public static byte[] nullVec = new byte[0];

    public sample()
    {
        usesTbs = CmdLine.isOptionPresent("tbs", "t");
        System.out.println("Connecting to " + (usesTbs ? "OS TPM" : "TPM Simulator"));
        tpm = usesTbs ? TpmFactory.platformTpm() : TpmFactory.localTpmSimulator();

        aesTemplate = new TPMT_PUBLIC(TPM_ALG_ID.SHA256,
                new TPMA_OBJECT(TPMA_OBJECT.decrypt, TPMA_OBJECT.sign, TPMA_OBJECT.fixedParent, TPMA_OBJECT.fixedTPM,
                        TPMA_OBJECT.userWithAuth),
                new byte[0],
                new TPMS_SYMCIPHER_PARMS(new TPMT_SYM_DEF_OBJECT(TPM_ALG_ID.AES,  128, TPM_ALG_ID.CFB)),
                new TPM2B_DIGEST_Symcipher());

        iv = new byte[2][];
    }



    public byte[] encrypt(byte[] toEncrypt, byte[] key, int ivType){
        // The key is passed in in the SENSITIVE_CREATE structure
        TPMS_SENSITIVE_CREATE sensCreate = new TPMS_SENSITIVE_CREATE(nullVec, key);

        // "Create" they key based on the externally provided keying data
        CreatePrimaryResponse aesPrimary = tpm.CreatePrimary(tpm._OwnerHandle, sensCreate, aesTemplate, nullVec,
                new TPMS_PCR_SELECTION[0]);
        TPM_HANDLE aesHandle = aesPrimary.handle;

        iv[ivType] = new byte[16];

       byte[] result =  tpm.EncryptDecrypt(aesHandle, (byte) 0, TPM_ALG_ID.CFB, iv[ivType], toEncrypt).outData;

       tpm.FlushContext(aesHandle);

       return result;
    }

    public byte[] decrypt(byte[] encrypted, byte[] key, int ivType){
        TPMS_SENSITIVE_CREATE sensCreate = new TPMS_SENSITIVE_CREATE(nullVec, key);

        CreatePrimaryResponse aesPrimary = tpm.CreatePrimary(tpm._OwnerHandle, sensCreate, aesTemplate, nullVec,
                new TPMS_PCR_SELECTION[0]);
        TPM_HANDLE aesHandle = aesPrimary.handle;

        byte[] result = tpm.EncryptDecrypt(aesHandle, (byte) 1, TPM_ALG_ID.CFB, iv[ivType],
                encrypted).outData;

        tpm.FlushContext(aesHandle);

        return result;

    }


}
