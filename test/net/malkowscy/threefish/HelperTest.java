package net.malkowscy.threefish;

import junit.framework.Assert;
import junit.framework.TestCase;

public class HelperTest extends TestCase {

	public void testConvert() {

		Assert.assertEquals("000102030405060708090A0B0C0D0E0F", Helper.convert("07060504.03020100  0F0E0D0C.0B0A0908"));
		Assert.assertEquals("101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F",
				Helper.convert("17161514.13121110  1F1E1D1C.1B1A1918  27262524.23222120  2F2E2D2C.2B2A2928"));

	}

}
