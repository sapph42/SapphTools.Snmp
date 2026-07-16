using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace SapphTools.Snmp.Messages;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public readonly struct Parameters2u {
    public byte Model { get; init; }
    public byte QoS { get; init; }
    public readonly byte[] AgentId { get; init; }
    public uint AgentBoots { get; init; }
    public uint AgentTime { get; init; }
    public ushort MaxSize { get; init; }
    public readonly byte UserLen => (byte)UserName.Length;
    public byte[] UserName { get; init; }
    public readonly byte AuthLen => (byte)AuthDigest.Length;
    public byte[] AuthDigest { get; init; } = [];
    public byte[] ContextSel { get; init; } = [];

    public Parameters2u(byte model, byte qos, byte[] agentId, uint agentBoots, uint agentTime, ushort maxSize, byte[] userName, byte[] authDigest, byte[] contextSel) {
        Model = model;
        QoS = qos;
        if (agentId.Length != 12) {
            throw new ArgumentException("AgentId must be exactly 12 bytes long.");
        }
        AgentId = agentId;
        AgentBoots = agentBoots;
        AgentTime = agentTime;
        MaxSize = maxSize;
        if (userName.Length < 0 || userName.Length > 16) {
            throw new ArgumentException("UserName must be between 0 and 16 bytes long.");
        }
        UserName = userName;
        if (authDigest.Length > 255) {
            throw new ArgumentException("AuthDigest must be at most 255 bytes long.");
        }
        AuthDigest = authDigest;
        if (contextSel.Length > 40) {
            throw new ArgumentException("ContextSel must be at most 40 bytes long.");
        }
        ContextSel = contextSel;
    }
    public readonly byte[] GetBytes() {
        Span<byte> agentBoots = stackalloc byte[4];
        Span<byte> agentTime = stackalloc byte[4];
        Span<byte> maxSize = stackalloc byte[2];
        BinaryPrimitives.WriteUInt32BigEndian(agentBoots, AgentBoots);
        BinaryPrimitives.WriteUInt32BigEndian(agentTime, AgentTime);
        BinaryPrimitives.WriteUInt16BigEndian(maxSize, MaxSize);
        return [
            Model,
            QoS,
            ..AgentId,
            ..agentBoots.ToArray(),
            ..agentTime.ToArray(),
            ..maxSize.ToArray(),
            UserLen,
            ..UserName,
            AuthLen,
            ..AuthDigest,
            ..ContextSel
        ];
    }
}

