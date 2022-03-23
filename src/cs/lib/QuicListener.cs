#nullable enable

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Threading.Tasks.Sources;

namespace Microsoft.Quic
{
    public class QuicListener : IAsyncDisposable
    {
        private readonly QuicRegistration Registration;
        private readonly ushort Port;
        private unsafe readonly QUIC_HANDLE* Listener;
        private readonly ReadOnlyMemory<byte> Alpn;
        private readonly ReadOnlyMemory<byte> PfxData;
        private readonly ManualResetValueTaskSource StoppedTaskSource = new ManualResetValueTaskSource();
        private bool Running = false;

        private sealed class ManualResetValueTaskSource : IValueTaskSource
        {
            private ManualResetValueTaskSourceCore<object?> Logic;

            public ManualResetValueTaskSource()
            {
                Logic = new ManualResetValueTaskSourceCore<object?>();
                Logic.RunContinuationsAsynchronously = true;
            }

            public void Set() => Logic.SetResult(null);
            public void Reset() => Logic.Reset();

            public short Version => Logic.Version;

            public void GetResult(short token) => Logic.GetResult(token);
            public ValueTaskSourceStatus GetStatus(short token) => Logic.GetStatus(token);
            public void OnCompleted(Action<object?> continuation, object? state, short token, ValueTaskSourceOnCompletedFlags flags) => Logic.OnCompleted(continuation, state, token, flags);  
        }

        [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
        private static unsafe int ListenerCallback(QUIC_HANDLE* Handle, void* Context, QUIC_LISTENER_EVENT* Event)
        {
            QuicListener Listener = (QuicListener)GCHandle.FromIntPtr((IntPtr)Context).Target!;
            switch (Event->Type)
            {
                case QUIC_LISTENER_EVENT_TYPE.QUIC_LISTENER_EVENT_NEW_CONNECTION:
                    break;
                case QUIC_LISTENER_EVENT_TYPE.QUIC_LISTENER_EVENT_STOP_COMPLETE:
                    Listener.StoppedTaskSource.Set();
                    break;
                default:
                    break;
            }

            return MsQuic.QUIC_STATUS_SUCCESS;
        }

        public unsafe QuicListener(QuicRegistration Registration, ReadOnlySpan<char> Alpn, ushort Port, ReadOnlySpan<byte> PfxData)
        {
            this.Registration = Registration;
            this.Port = Port;
            QUIC_HANDLE* LocalListener = null;

            byte[] LocalAlpn = new byte[Encoding.UTF8.GetByteCount(Alpn)];
            int AlpnLength = Encoding.UTF8.GetBytes(Alpn, LocalAlpn);
            this.Alpn = LocalAlpn.AsMemory().Slice(0, AlpnLength);

            byte[] LocalPfxData = new byte[PfxData.Length];
            PfxData.CopyTo(LocalPfxData);
            this.PfxData = LocalPfxData;

            void* ListenerThis = (void*)(IntPtr)GCHandle.Alloc(this);
            try
            {
                int Status = Registration.ApiTable.ListenerOpen(Registration.Registration, &ListenerCallback, ListenerThis, &LocalListener);
                MsQuic.ThrowIfFailure(Status);
                Listener = LocalListener;
            } catch
            {
                if (LocalListener != null)
                {
                    Registration.ApiTable.ListenerClose(LocalListener);
                }
                GCHandle.FromIntPtr((IntPtr)ListenerThis).Free();
                throw;
            }
        }

        public unsafe void Start()
        {
            if (Running)
            {
                return;
            }
            fixed (byte* AlpnPtr = Alpn.Span) {
                QUIC_BUFFER Buffer;
                Buffer.Buffer = AlpnPtr;
                Buffer.Length = (uint)Alpn.Length;
                QuicAddr Addr = new QuicAddr();
                Addr.Ipv4.sin_port = (ushort)IPAddress.HostToNetworkOrder((short)Port);
                int Status = Registration.ApiTable.ListenerStart(Listener, &Buffer, 1, &Addr);
                MsQuic.ThrowIfFailure(Status);
            }
            Running = true;
            StoppedTaskSource.Reset();
        }

        public unsafe void Stop()
        {
            if (!Running)
            {
                return;
            }
            Running = false;
            Registration.ApiTable.ListenerStop(Listener);
        }

        public async ValueTask DisposeAsync()
        {
            unsafe
            {
                if (Listener == null)
                {
                    return;
                }
                Registration.ApiTable.ListenerStop(Listener);
            }
            await new ValueTask(StoppedTaskSource, StoppedTaskSource.Version);
            unsafe
            {
                Registration.ApiTable.ListenerClose(Listener);
            }
        }
    }
}
