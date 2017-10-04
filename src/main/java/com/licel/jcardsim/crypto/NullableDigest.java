package com.licel.jcardsim.crypto;

import org.bouncycastle.crypto.Digest;

import java.io.ByteArrayOutputStream;

public class NullableDigest implements Digest {
  private Digest digest;
  private boolean isNulled;
  private ByteArrayOutputStream bos;

  public NullableDigest(Digest digest) {
    this.digest = digest;
    this.bos = new ByteArrayOutputStream();
  }

  public String getAlgorithmName() {
    return digest.getAlgorithmName();
  }

  public int getDigestSize() {
    return digest.getDigestSize();
  }

  public void update(byte in) {
    if (isNulled) {
      this.bos.write(in);
    } else {
      this.digest.update(in);
    }
  }

  public void update(byte[] in, int off, int len) {
    if (isNulled) {
      this.bos.write(in, off, len);
    } else {
      this.digest.update(in, off, len);
    }
  }

  public int doFinal(byte[] out, int off) {
    if (isNulled) {
      byte[] res = bos.toByteArray();
      System.arraycopy(res, 0, out, off, res.length);
      this.bos.reset();
      return res.length;
    } else {
      return this.digest.doFinal(out, off);
    }
  }

  public void reset() {
    if (isNulled) {
      this.bos.reset();
    } else {
      this.digest.reset();
    }
  }

  public boolean isNulled() {
    return isNulled;
  }

  public void setNulled(boolean nulled) {
    isNulled = nulled;
    this.bos.reset();
    this.digest.reset();
  }
}
