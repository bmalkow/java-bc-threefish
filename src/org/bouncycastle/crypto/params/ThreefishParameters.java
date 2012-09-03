package org.bouncycastle.crypto.params;

public class ThreefishParameters extends KeyParameter {

	private final byte[] tweak;

	public ThreefishParameters(byte[] key, byte[] tweak) {
		super(key);
		this.tweak = tweak;
	}

	public byte[] getTweak() {
		return tweak;
	}

}
