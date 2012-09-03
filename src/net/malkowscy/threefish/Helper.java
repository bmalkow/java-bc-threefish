package net.malkowscy.threefish;

public class Helper {

	public static String convert(String t) {
		System.out.println(t);
		t = t.replace(" ", "").replace(".", "").trim();
		String result = "";

		for (int i = 0; i < t.length(); i += 2) {
			int m = 16 + (i / 16) * 16;
			int j0 = m - (i % 16) - 1;
			int j1 = j0 - 1;

			String s = "" + t.charAt(j1) + t.charAt(j0);

			result += s;
		}

		System.out.println(result);

		System.out.println();
		return result;
	}

	public static void main(String[] args) {
		convert("17161514.13121110  1F1E1D1C.1B1A1918  27262524.23222120  2F2E2D2C.2B2A2928      37363534.33323130  3F3E3D3C.3B3A3938  47464544.43424140  4F4E4D4C.4B4A4948     57565554.53525150  5F5E5D5C.5B5A5958  67666564.63626160  6F6E6D6C.6B6A6968     77767574.73727170  7F7E7D7C.7B7A7978  87868584.83828180  8F8E8D8C.8B8A8988");
		convert("B0C33CD7.DB4D65A6  BC49A85A.1077D75D  6855FCAF.EA7293E4  1C5385AB.1B7754D2     30E4AAFF.E780F794  E1BBEE70.8CAFD8D5  9CA837B7.423B0F76  BD140367.0D4963B3     451F2E3C.E61EA48A  B360832F.9277D4FB  0AAFC7A6.5E12D688  C8906E79.016D05D7     B316570A.15F41333  74E98A28.69F5D50E  57CE6F92.47432BCE  DE7CDD77.215144DE");
	}

}
