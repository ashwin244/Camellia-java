

import java.util.Arrays;

/**
 * 
 * @author ASHWIN
 *
 */
public class Main_Byte_Output {

	private static final int MASK8 = 0xff;
	private static final int MASK32 = 0xffffffff;
	private static enum KeyType { KEY_128, KEY_192, KEY_256};
	private static final int[] Sigma = {
		   0xA09E667F, 0x3BCC908B,
		   0xB67AE858, 0x4CAA73B2,
		   0xC6EF372F, 0xE94F82BE,
		   0x54FF53A5, 0xF1D36F1C,
		   0x10E527FA, 0xDE682D1D,
		   0xB05688C2, 0xB3E6C1FD};
	
	private static final int SBOX1[] = { 112, 130, 44, 236, 179, 39, 192, 229,
			228, 133, 87, 53, 234, 12, 174, 65, 35, 239, 107, 147, 69, 25, 165,
			33, 237, 14, 79, 78, 29, 101, 146, 189, 134, 184, 175, 143, 124,
			235, 31, 206, 62, 48, 220, 95, 94, 197, 11, 26, 166, 225, 57, 202,
			213, 71, 93, 61, 217, 1, 90, 214, 81, 86, 108, 77, 139, 13, 154,
			102, 251, 204, 176, 45, 116, 18, 43, 32, 240, 177, 132, 153, 223,
			76, 203, 194, 52, 126, 118, 5, 109, 183, 169, 49, 209, 23, 4, 215,
			20, 88, 58, 97, 222, 27, 17, 28, 50, 15, 156, 22, 83, 24, 242, 34,
			254, 68, 207, 178, 195, 181, 122, 145, 36, 8, 232, 168, 96, 252,
			105, 80, 170, 208, 160, 125, 161, 137, 98, 151, 84, 91, 30, 149,
			224, 255, 100, 210, 16, 196, 0, 72, 163, 247, 117, 219, 138, 3,
			230, 218, 9, 63, 221, 148, 135, 92, 131, 2, 205, 74, 144, 51, 115,
			103, 246, 243, 157, 127, 191, 226, 82, 155, 216, 38, 200, 55, 198,
			59, 129, 150, 111, 75, 19, 190, 99, 46, 233, 121, 167, 140, 159,
			110, 188, 142, 41, 245, 249, 182, 47, 253, 180, 89, 120, 152, 6,
			106, 231, 70, 113, 186, 212, 37, 171, 66, 136, 162, 141, 250, 114,
			7, 185, 85, 248, 238, 17, 10, 54, 73, 42, 104, 60, 56, 241, 164,
			64, 40, 211, 123, 187, 201, 67, 193, 21, 227, 173, 244, 119, 199,
			128, 158 };
	
	private static int[] KL = new int[4];     // Encryption key
	private static int[] KR = new int[4];     // Encryption key
	private static final int[] K = new int[8];     // Encryption key
	private static int[] k = new int[24 * 2];
	private static int[] kDec = new int[24 * 2];
	private static int[] KA = new int[4];     
	private static int[] KB = new int[4];
	
	
	private static int[] kw = new int[4 * 2];
	private static int[] ke = new int[6 * 2];
	
	private static int[] kwDec = new int[4 * 2];
	private static int[] keDec = new int[6 * 2];

	public static int[] Xor128(int[] left, int[] right){
		int [] result = new int [4];
		for(int i = 0; i < 4; i++) {
			result[i] = left[i] ^ right[i];
		}
		return result;
	}
	
	public static int[] Xor64(int[] left, int[] right, int offset){
		int [] result = new int [2];
		for(int i = 0; i < 2; i++) {
			result[i] = left[i] ^ right[i + offset];
		}
		return result;
	}
	
    private final static int bytes2Int(byte[] src, int offset) {
	int word=0;

	for(int i = 0; i< 4; i++) {
	    word = ((word << 8) + (src[i+offset] & MASK8));  
	}
	return word & 0xffffffff;
    }
     
    private final static void int2bytes(int word, byte[] dst, int offset) {
	for(int i = 0; i< 4; i++) {
	    dst[(3-i)+offset] = (byte)word;
	    word >>>= 8;
	}
    }
    
    
	//key scheduling part
	private static void keySchedule(byte[] key, int keyType) {
		if (keyType == KeyType.KEY_128.ordinal()) {
			
		    K[0] = bytes2Int(key, 0);
		    K[1] = bytes2Int(key, 4);
		    K[2] = bytes2Int(key, 8);
		    K[3] = bytes2Int(key, 12);
		    K[4] = K[5] = K[6] = K[7] = 0;
		}
		if (keyType == KeyType.KEY_192.ordinal()) {
			//KL = rotateRight(key, 64);
		    K[0] = bytes2Int(key, 0);
		    K[1] = bytes2Int(key, 4);
		    K[2] = bytes2Int(key, 8);
		    K[3] = bytes2Int(key, 12);
		    K[4] = bytes2Int(key, 16);
		    K[5] = bytes2Int(key, 20);
		    K[6] = ~K[4];
		    K[7] = ~K[5];
		}
		if (keyType == KeyType.KEY_256.ordinal()) {
		    K[0] = bytes2Int(key, 0);
		    K[1] = bytes2Int(key, 4);
		    K[2] = bytes2Int(key, 8);
		    K[3] = bytes2Int(key, 12);
		    K[4] = bytes2Int(key, 16);
		    K[5] = bytes2Int(key, 20);
		    K[6] = bytes2Int(key, 24);
		    K[7] = bytes2Int(key, 28);
		}
		
		KL = Arrays.copyOfRange(K, 0, 4);
		KR = Arrays.copyOfRange(K, 4, 8);
		
		int[] D1 = new int[2];
		int[] D2 = new int[2];
		
		//KA and KB
		   D1 = Arrays.copyOfRange(Xor128(KL, KR), 0, 2); // change (Xor128(KL, KR)) >> 64    
		   D2 = Arrays.copyOfRange(Xor128(KL, KR), 2, 4);//(bytesToLong(KL) ^ bytesToLong(KR)) & MASK64;  // change
		   
		   D2 = Xor64(D2, F(D1, Sigma, 0), 0);
		   D1 = Xor64(D1, F(D2, Sigma, 2), 0);
		   
		   D1 = Xor64(D1,  Arrays.copyOfRange(KL, 0, 2), 0);
		   D2 = Xor64(D2,  Arrays.copyOfRange(KL, 2, 4), 0);
		   
		   D2 = Xor64(D2, F(D1, Sigma, 4), 0);
		   D1 = Xor64(D1, F(D2, Sigma, 6), 0);
		   	
		   KA[0] = D1[0];
		   KA[1] = D1[1];	
		   KA[2] = D2[0];
		   KA[3] = D2[1];
		   
		   D1 = Arrays.copyOfRange(Xor128(KA, KR), 0, 2); // D1 = (KA ^ bytesToLong(KR)) >> 64;
		   D2 = Arrays.copyOfRange(Xor128(KA, KR), 2, 4);//D2 = (KA ^ bytesToLong(KR)) & MASK64;
		   
		   D2 = Xor64(D2, F(D1, Sigma, 8), 0);
		   D1 = Xor64(D1, F(D2, Sigma, 10), 0);
		   
		   KB[0] = D1[0];
		   KB[1] = D1[1];	
		   KB[2] = D2[0];
		   KB[3] = D2[1];
		   
		   
		   
		   /////////////////////// SUBKEYS   ///////////////////////////////
		   
		   if (keyType == KeyType.KEY_128.ordinal()) {
			   
		   kw[0] = KL[0];
		   kw[1] = KL[1];
		   kw[2] = KL[2];
		   kw[3] = KL[3];
		   
		   k[0]  = KA[0];
		   k[1]  = KA[1];
		   
		   k[2]  = KA[2];
		   k[3]  = KA[3];
		   
		   rotate32(15, KL, k, 4);
		   rotate32(15, KA, k, 8);
		   
		   rotate32(30, KA, ke, 0);
		   
		   rotate64(45, KL, k, 12);
		   
		   
			k[16] = (KL[1] << (45 - 32)) | (KA[2] >>> (64 - 45- 1));
			k[17] = (KL[2] << (45 - 32)) | (KA[3] >>> (64 - 45- 1));
			
			k[18] = (KA[3] << (60 - 32));
			k[19] = 0;
			
			rotate64(60, KA, k, 20);
			
			rotate96(77, KL, ke, 4);
			
			rotate96(94, KL, k, 24);
			rotate96(94, KA, k, 28);
			
			rotate128(111, KL, k, 32);
			rotate128(111, KA, kw, 4);
		   }
		   
		   if (keyType == KeyType.KEY_192.ordinal() || keyType ==  KeyType.KEY_256.ordinal()) {
			   kw[0] = KL[0];
			   kw[1] = KL[1];
			   kw[2] = KL[2] & MASK32;
			   kw[3] = KL[3] & MASK32;
			   
			   k[0]  = KB[2];
			   k[1]  = KB[3];
			   
			   k[2]  = KB[0];
			   k[3]  = KB[1];
			   
			   rotate32(15, KR, k, 4);
			   rotate32(15, KA, k, 8);
			   
			   rotate32(30, KR, ke, 0);
			   rotate32(30, KB, k, 12);
			   
			   rotate64(45, KL, k, 16);
			   rotate64(45, KA, k, 20);
			   
				rotate64(60, KL, ke, 4);
				rotate64(60, KR, k, 24);
				rotate64(60, KB, k, 28);
				
				rotate96(77, KA, k, 32);
				rotate96(77, KL, ke, 8);

				rotate96(94, KR, k, 36);
				rotate96(94, KA, k, 40);
				
				rotate128(111, KL, k, 44);
				rotate128(111, KB, kw, 4);
		   }
	}
	
	
	
	
	private static int[] F(int[] Fin, int[] KE, int offset){
		int[] x = new int[2];  
		int t1, t2, t3, t4, t5, t6, t7, t8;
		int y1, y2, y3, y4, y5, y6, y7, y8;
		int[] F_OUT =  new int[2];
		
		x[0] = Fin[0] ^ KE[0 + offset];
		x[1] = Fin[1] ^ KE[1 + offset];
		
	       t1 =   ((x[0] >>> 24) & MASK8);
	       t2 =   ((x[0] >>> 16) & MASK8);
	       t3 =  ((x[0] >>> 8) & MASK8);
	       t4 =  ((x[0]) & MASK8);
	       t5 =  ((x[1] >>> 24) & MASK8);
	       t6 =  ((x[1] >>> 16) & MASK8);
	       t7 =  ((x[1] >>>  8) & MASK8);
	       t8 =  (x[1]& MASK8);
	       
	       t1 =  SBOX1[t1];
	       t2 = (SBOX1[t2] << 1)& MASK8; //SBOX2[t2];
	       t3 = (SBOX1[t3] << 7)& MASK8; //SBOX3[t3];
	       t4 = (SBOX1[(t4 << 1) & MASK8])& MASK8; //SBOX4[t4];
	       t5 = (SBOX1[t5] << 1)& MASK8; //SBOX2[t5];
	       t6 = (SBOX1[t6] << 7)& MASK8; //SBOX3[t6];
	       t7 = (SBOX1[(t7 << 1) & MASK8])& MASK8; //SBOX4[t7];
	       t8 =  SBOX1[t8];
	       
	       y1 =  (t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8);
	       y2 =  (t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8);
	       y3 =  (t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8);
	       y4 =  (t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7);
	       y5 =  (t1 ^ t2 ^ t6 ^ t7 ^ t8);
	       y6 =  (t2 ^ t3 ^ t5 ^ t7 ^ t8);
	       y7 =  (t3 ^ t4 ^ t5 ^ t6 ^ t8);
	       y8 =  (t1 ^ t4 ^ t5 ^ t6 ^ t7);
	       F_OUT[0] = (y1 << 24) | (y2 << 16) | (y3 << 8) | y4;
	       F_OUT[1] = (y5 << 24) | (y6 << 16) | (y7 <<  8) | y8;
	       return F_OUT;
	}
	
	private static int[] dataRandomizingPart (byte[] message, int keyType){
		
		int[] D1 = new int[2];
		int[] D2 = new int[2];
		int[] cipher = new int[4];
		D1[0] = bytes2Int(message, 0);
		D1[1] = bytes2Int(message, 4);
		D2[0] = bytes2Int(message, 8);
		D2[1] = bytes2Int(message, 12);
		
		if (keyType == KeyType.KEY_128.ordinal()) {
			//Pre-Whitening
			D1 = Xor64(D1, kw, 0);  
			D2 = Xor64(D2, kw, 2);
			
			D2 = Xor64(D2, F(D1, k, 0), 0); //round 1
			D1 = Xor64(D1, F(D2, k, 2), 0); //round 2
			D2 = Xor64(D2, F(D1, k, 4), 0); //round 3
			D1 = Xor64(D1, F(D2, k, 6), 0); //round 4
			D2 = Xor64(D2, F(D1, k, 8), 0); //round 5
			D1 = Xor64(D1, F(D2, k, 10), 0); //round 6
			
			D1 = FL(D1, ke, 0);     // FL
			D2 = FLINV(D2, ke, 2);     // FLINV
			
			D2 = Xor64(D2, F(D1, k, 12), 0); //round 7
			D1 = Xor64(D1, F(D2, k, 14), 0); //round 8
			D2 = Xor64(D2, F(D1, k, 16), 0); //round 9
			D1 = Xor64(D1, F(D2, k, 18), 0); //round 10
			D2 = Xor64(D2, F(D1, k, 20), 0); //round 11
			D1 = Xor64(D1, F(D2, k, 22), 0); //round 12
			
			D1 = FL   (D1, ke, 4);     // FL
			D2 = FLINV (D2, ke, 6);     // FLINV
			
			D2 = Xor64(D2, F(D1, k, 24), 0); //round 13
			D1 = Xor64(D1, F(D2, k, 26), 0); //round 14
			D2 = Xor64(D2, F(D1, k, 28), 0); //round 15
			D1 = Xor64(D1, F(D2, k, 30), 0); //round 16
			D2 = Xor64(D2, F(D1, k, 32), 0); //round 17
			D1 = Xor64(D1, F(D2, k, 34), 0); //round 18
			
			//Post-whitening
			D2 = Xor64(D2, kw, 4);  
			D1 = Xor64(D1, kw, 6); 
			
		}
		
		if (keyType == KeyType.KEY_192.ordinal() || keyType == KeyType.KEY_256.ordinal()) {
			//Pre-whitening
			D1 = Xor64(D1, kw, 0);  
			D2 = Xor64(D2, kw, 2);
			
			D2 = Xor64(D2, F(D1, k, 0), 0); //round 1
			D1 = Xor64(D1, F(D2, k, 2), 0); //round 2
			D2 = Xor64(D2, F(D1, k, 4), 0); //round 3
			D1 = Xor64(D1, F(D2, k, 6), 0); //round 4
			D2 = Xor64(D2, F(D1, k, 8), 0); //round 5
			D1 = Xor64(D1, F(D2, k, 10), 0); //round 6
			
			D1 = FL(D1, ke, 0);     // FL
			D2 = FLINV(D2, ke, 2);     // FLINV
			
			D2 = Xor64(D2, F(D1, k, 12), 0); //round 7
			D1 = Xor64(D1, F(D2, k, 14), 0); //round 8
			D2 = Xor64(D2, F(D1, k, 16), 0); //round 9
			D1 = Xor64(D1, F(D2, k, 18), 0); //round 10
			D2 = Xor64(D2, F(D1, k, 20), 0); //round 11
			D1 = Xor64(D1, F(D2, k, 22), 0); //round 12
			
			D1 = FL   (D1, ke, 4);     // FL
			D2 = FLINV (D2, ke, 6);     // FLINV
			
			D2 = Xor64(D2, F(D1, k, 24), 0); //round 13
			D1 = Xor64(D1, F(D2, k, 26), 0); //round 14
			D2 = Xor64(D2, F(D1, k, 28), 0); //round 15
			D1 = Xor64(D1, F(D2, k, 30), 0); //round 16
			D2 = Xor64(D2, F(D1, k, 32), 0); //round 17
			D1 = Xor64(D1, F(D2, k, 34), 0); //round 18
			
			D1 = FL   (D1, ke, 8);     // FL
			D2 = FLINV (D2, ke, 10);     // FLINV
			
			D2 = Xor64(D2, F(D1, k, 36), 0); //round 19
			D1 = Xor64(D1, F(D2, k, 38), 0); //round 20
			D2 = Xor64(D2, F(D1, k, 40), 0); //round 21
			D1 = Xor64(D1, F(D2, k, 42), 0); //round 22
			D2 = Xor64(D2, F(D1, k, 44), 0); //round 23
			D1 = Xor64(D1, F(D2, k, 46), 0); //round 24
		}
		
		cipher[0] = D2[0];
		cipher[1] = D2[1];
		cipher[2] = D1[0];
		cipher[3] = D1[1];
		return cipher;
	}
	
	
	private static int[] FL(int[] FLin, int[] KE, int offset){
		int x1, x2;
		int k1, k2;
		int[] FL_OUT = new int[2];
	       x1 = FLin[0];
	       x2 = FLin[1];
	       k1 = KE[0];
	       k2 = KE[1];
	       x2 = x2 ^ ((x1 & k1) << 1);
	       x1 = x1 ^ (x2 | k2);
	       FL_OUT[0] = x1;
	       FL_OUT[1] = x2;
	       return FL_OUT;
	}
	
	private static int[] FLINV(int[] FLINVin, int[] KE, int offset){
		int y1, y2;
		int k1, k2;
		int[] FLINV_OUT = new int[2]; 
			y1 = FLINVin[0];
	       y2 = FLINVin[1];
	       k1 = KE[0];
	       k2 = KE[1];
	       y1 = y1 ^ (y2 | k2);
	       y2 = y2 ^ ((y1 & k1) << 1);
	       FLINV_OUT[0] = y1;
	       FLINV_OUT[1] = y2;
	       return FLINV_OUT;
	}
	
	private static final void rotate32(int rot, int[] ki, int[] ko, int offset) {
		ko[0 + offset] = (ki[0] << rot) | (ki[1] >>> (32 - rot));
		ko[1 + offset] = (ki[1] << rot) | (ki[2] >>> (32 - rot));
		ko[2 + offset] = (ki[2] << rot) | (ki[3] >>> (32 - rot));
		ko[3 + offset] = (ki[3] << rot);
	}
    
	private static final void rotate64(int rot, int[] ki, int[] ko, int offset) {
		ko[0 + offset] = (ki[1] << (rot - 32)) | (ki[2] >>> (64 - rot));
		ko[1 + offset] = (ki[2] << (rot - 32)) | (ki[3] >>> (64 - rot));
		ko[2 + offset] = (ki[3] << (rot - 32));
		ko[3 + offset] = 0;
	}
	
	private static final void rotate96(int rot, int[] ki, int[] ko, int offset) {
		ko[0 + offset] = (ki[2] << (rot - 64)) | (ki[3] >>> (96 - rot));
		ko[1 + offset] = (ki[3] << (rot - 64));
		ko[2 + offset] = 0;
		ko[3 + offset] = 0;
	}
	
	private static final void rotate128(int rot, int[] ki, int[] ko, int offset) {
		ko[2 + offset] = (ki[3] << (128 - rot));
		ko[3 + offset] = 0;
		ko[0 + offset] = 0;
		ko[1 + offset] = 0;
	}
    
	
	
	public static void init(byte[] key, byte[] message, int keyType){
		keySchedule(key, keyType);
		int[] cipher = dataRandomizingPart(message, keyType);
		byte[] dst = new byte[32];
		int offset = 0;
		for(int c : cipher){
			int2bytes(c, dst,offset); 
			offset +=4;
		}
		System.out.println("Message");
		for (byte m: message){
			System.out.print(" "+m);
		} 
		System.out.println("\nCipher Text");
		for (byte d: dst){
			System.out.print(" "+d);
		} 
	    kwDec = kw;
	    keDec = ke;
	    kDec = k;
	    
	       kw[0]  = kwDec[4];
	       kw[1]  = kwDec[5];
	       kw[2]  = kwDec[6];
	       kw[3]  = kwDec[7];
	       kw[4]  = kwDec[0];
	       kw[5]  = kwDec[1];
	       kw[6]  = kwDec[2];
	       kw[7]  = kwDec[3];
	       
	       k[0]  = kDec[34];
	       k[1]  = kDec[35];
	       k[34]  = kDec[0];
	       k[35]  = kDec[1];
	       
	       k[2]  = kDec[32];
	       k[3]  = kDec[33];
	       k[32]  = kDec[2];
	       k[33]  = kDec[3];
	       
	       k[4]  = kDec[30];
	       k[5]  = kDec[31];
	       k[30]  = kDec[4];
	       k[31]  = kDec[5];
	       
	       k[6]  = kDec[28];
	       k[7]  = kDec[29];
	       k[28]  = kDec[6];
	       k[29]  = kDec[7];
	       
	       k[8]  = kDec[26];
	       k[9]  = kDec[27];
	       k[26]  = kDec[8];
	       k[27]  = kDec[9];
	       
	       k[10]  = kDec[24];
	       k[11]  = kDec[25];
	       k[24]  = kDec[10];
	       k[25]  = kDec[11];
	       
	       k[12]  = kDec[22];
	       k[13]  = kDec[23];
	       k[22]  = kDec[12];
	       k[23]  = kDec[13];
	       
	       k[14]  = kDec[20];
	       k[15]  = kDec[21];
	       k[20]  = kDec[14];
	       k[21]  = kDec[15];
	       
	       k[16]  = kDec[18];
	       k[17]  = kDec[19];
	       k[18]  = kDec[16];
	       k[19]  = kDec[17];
	       
	       ke[0]  = keDec[6];
	       ke[1]  = keDec[7];
	       ke[2]  = keDec[4];
	       ke[3]  = keDec[5];
	       ke[6]  = keDec[0];
	       ke[7]  = keDec[1];
	       ke[4]  = keDec[2];
	       ke[5]  = keDec[3];
	       
	       
	       int[] decryptMessage = dataRandomizingPart(dst, keyType);
	       byte[] dst1 = new byte[32];
	       offset = 0;
			for(int d : decryptMessage){
				int2bytes(d, dst1, offset); 
				offset +=4;
			}
			System.out.println("\ndec Message");
			for (byte d: dst1){
				System.out.print(" "+d);
			} 
			
	}
	
	
	
	public static void main(String[] args){
		byte[] key = {0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef, 
				(byte) 0xfe, (byte) 0xdc, (byte) 0xba, (byte) 0x98, 0x76, 0x54, 0x32, 0x10};
		
		byte[] msg = {0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef, 
				(byte) 0xfe, (byte) 0xdc, (byte) 0xba, (byte) 0x98, 0x76, 0x54, 0x32, 0x10};
		init(key, msg, KeyType.KEY_128.ordinal());
	}
	
}


