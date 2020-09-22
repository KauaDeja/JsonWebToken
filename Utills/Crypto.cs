using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace API_Nyous.Utills
{
    public class Crypto
    {
		public static string Criptografar(string Txt, string Salt)
		{
			using (SHA256 sha501Hash = SHA256.Create())
			{

				byte[] bytes = sha501Hash.ComputeHash(Encoding.UTF8.GetBytes(Salt + Txt));

				StringBuilder builder = new StringBuilder();
				for (int i = 0; i < bytes.Length; i++)
				{
					builder.Append(bytes[i].ToString("x2"));
				}
				return builder.ToString();
			}
		}
	}
}
