using System;
using System.Text;

namespace Microsoft.Quic
{
    public class QuicRegistration : IDisposable
    {
        private unsafe QUIC_API_TABLE* _ApiTable;
        private unsafe QUIC_HANDLE* _Registration;

        public static unsafe implicit operator QUIC_HANDLE*(QuicRegistration Reg)
        {
            return Reg._Registration;
        }

        public unsafe QUIC_HANDLE* Registration => _Registration;

        public ref readonly QUIC_API_TABLE ApiTable => ref ApiTable;

        public unsafe QuicRegistration(string RegistrationName)
        {
            _ApiTable = MsQuic.Open();
            try
            {
                QUIC_REGISTRATION_CONFIG RegConfig = new QUIC_REGISTRATION_CONFIG();
                RegConfig.ExecutionProfile = 0;
                int ByteCount = Encoding.UTF8.GetByteCount(RegistrationName);
                byte[] RegBytes = new byte[ByteCount];
                int ActualByteCount = Encoding.UTF8.GetBytes(RegistrationName, RegBytes);
                RegBytes[ActualByteCount] = 0;
                fixed (byte* RegBytesPtr = RegBytes)
                {
                    RegConfig.AppName = (sbyte*)RegBytesPtr;
                    QUIC_HANDLE* LocalReg = null;
                    int Status = ApiTable.RegistrationOpen(&RegConfig, &LocalReg);
                    MsQuic.ThrowIfFailure(Status);
                    _Registration = LocalReg;
                }
            }
            catch
            {
                MsQuic.Close(_ApiTable);
                _ApiTable = null;
                throw;
            }
        }

        public unsafe void Dispose()
        {
            if (_Registration != null)
            {
                ApiTable.RegistrationClose(_Registration);
                MsQuic.Close(_ApiTable);
            }
        }
    }
}
