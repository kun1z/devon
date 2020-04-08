#include <stdint.h>
#include <string.h>
//----------------------------------------------------------------------------------------------------------------------
// E8CB4A77D58178CF7080C7FBE0623353DA0E46879D636702B03159E840CB8630A323A08852C97D71E0B5E04CC1B2BA960B3EE3EA04FEC46FEE8B66BD0CD8F491
// AF9134F046862470A1D8FC6BCEB987EF69B6C92982F88317248C566E71689C273BEA93E57EF98FBDC92272EAF67D3952D840B47E03A08934205559006327C711
// 6E75DFCB1199796FE9BF1243E1C3D8B9850F8BD67F990A82781D86C399EB774634D05A914DAD708D2BEED3E96A6962D2062ADEFD8C1CDD54FE10F97A65065596
//----------------------------------------------------------------------------------------------------------------------
void sha2_512mod2(void * const out64, void const * const in64, void const * const in64_2, void const * const key64, void const * const key640)
{
    uint64_t IV[8] =
    {
        0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
        0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
    };

    uint64_t K[80] =
    {
        0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
        0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
        0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
        0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
        0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
        0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
        0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
        0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
        0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
        0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
        0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
        0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
        0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
        0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
        0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
        0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
        0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
        0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
        0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
        0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817,
    };

    if (key64)
    {
        for (int i=0;i<64;i++)
        {
            unsigned char const * const k = key64;
            unsigned char * const iv = (unsigned char*)IV;
            iv[i] ^= k[i];
        }
    }

    if (key640)
    {
        for (int i=0;i<640;i++)
        {
            unsigned char const * const k = key640;
            unsigned char * const kc = (unsigned char*)K;
            kc[i] ^= k[i];
        }
    }

    uint64_t S[8], W[80];

    memcpy(S, IV, 64);
    memcpy(W, in64, 64);

    if (in64_2)
    {
        memcpy(&W[8], in64_2, 64);
    }
    else
    {
        memset(&W[8], 0, 64);
    }

    for (int i=16;i<80;i++)
    {
        #define S0(x) (((x>>1)|(x<<63))^((x>>8)|(x<<56))^(x>>7))
        #define S1(x) (((x>>19)|(x<<45))^((x>>61)|(x<<63))^(x>>6))

        W[i] = S1(W[i-2]) + W[i-7] + S0(W[i-15]) + W[i-16];
    }

    uint8_t m[8] = { 0, 1, 2, 3, 4, 5, 6, 7 };

    for (int i=0;i<80;i++)
    {
        #define F0(x,y,z) ((x&y)|(z&(x|y)))
        #define F1(x,y,z) (z^(x&(y^z)))
        #define S2(x) (((x>>28)|(x<<36))^((x>>34)|(x<<30))^((x>>39)|(x<<25)))
        #define S3(x) (((x>>14)|(x<<50))^((x>>18)|(x<<46))^((x>>41)|(x<<23)))

        const uint64_t t1 = S[m[7]] + S3(S[m[4]]) + F1(S[m[4]], S[m[5]], S[m[6]]) + K[i] + W[i];
        S[m[3]] += t1;
        S[m[7]] = t1 + S2(S[m[0]]) + F0(S[m[0]], S[m[1]], S[m[2]]);

        for (int j=0;j<8;j++)
        {
            m[j] = (m[j] - 1) & 7;
        }
    }

    for (int i=0;i<8;i++)
    {
        unsigned char * const restrict p = out64;
        const uint64_t output = IV[i] + S[i];
        memcpy(&p[i * 8], &output, 8);
    }
}
//----------------------------------------------------------------------------------------------------------------------