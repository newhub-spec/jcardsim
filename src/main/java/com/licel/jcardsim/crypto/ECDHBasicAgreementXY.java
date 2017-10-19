package com.licel.jcardsim.crypto;

import org.bouncycastle.crypto.BasicAgreement;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public class ECDHBasicAgreementXY implements BasicAgreement {
  private ECPrivateKeyParameters key;

  public ECDHBasicAgreementXY() {
  }

  public void init(CipherParameters cipherParameters) {
    this.key = (ECPrivateKeyParameters)cipherParameters;
  }

  public BigInteger calculateAgreement(CipherParameters cipherParameters) {
    ECPublicKeyParameters publicKeyParameters = (ECPublicKeyParameters)cipherParameters;
    ECPoint ecPoint = publicKeyParameters.getQ().multiply(this.key.getD());
    return new BigInteger(ecPoint.getEncoded());
  }
}
