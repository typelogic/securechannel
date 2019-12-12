package dx;

import javacard.framework.APDU;
import javacard.framework.APDUException;
import javacard.framework.Applet;
import javacard.framework.AppletEvent;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacardx.apdu.ExtendedLength;

import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;

import javacard.framework.JCSystem;

public class CafeBabeApplet extends Applet
{
    private static final byte[] helloWorld
        = {'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'};

    private static final byte INS_HELLOWORLD = (byte)0x00;
    private static final byte INS_POKE = (byte)0x01;
    private static final byte INS_ECHO = (byte)0x02;
    private static final byte INS_CONTROL = (byte)0x03;

    private final static short LENGTH_APDU_EXTENDED = (short)0x7FFF;

    private static final byte INS_INITIALIZE_UPDATE = (byte)0x50;
    private static final byte INS_BEGIN_RMAC_SESSION = (byte)0x7A;
    private static final byte INS_END_RMAC_SESSION = (byte)0x78;

    protected static final byte MASK_GP = (byte)0x80;
    protected static final byte MASK_SECURED = (byte)0x0C;
    protected static final byte STATUS_LEN = (byte)0x08;
    protected static final byte CONTROL_LEN = (byte)0x03;

    public static final byte BYTE_00 = (byte)0x00;
    public static final short SHORT_00 = (short)0x0000;

    private byte[] apduData;
    protected byte cla;
    protected byte ins;
    protected byte p1;
    protected byte p2;

    private byte[] m_status;
    private byte[] m_control;
    private byte[] m_memo;

    private SecureChannel secureChannel;

    public static void requestObjectDeletion()
    {
        if (JCSystem.isObjectDeletionSupported()) {
            JCSystem.requestObjectDeletion();
        }
    }

    CafeBabeApplet()
    {
        m_status = new byte[STATUS_LEN];
        m_control = new byte[CONTROL_LEN];
    }

    public boolean select()
    {
        /* select -> process -> processSelect */
        secureChannel = GPSystem.getSecureChannel();
        m_status[1] = (byte)(m_status[1] | 1);
        return true;
    }

    public void processSelect()
    {
        if (!selectingApplet()) {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }

        ins_poke();
    }

    public void process(APDU apdu) throws ISOException
    {
        try {
            byte[] buffer = apdu.getBuffer();
            cla = buffer[ISO7816.OFFSET_CLA];
            ins = buffer[ISO7816.OFFSET_INS];
            p1 = buffer[ISO7816.OFFSET_P1];
            p2 = buffer[ISO7816.OFFSET_P2];

            // ISO class
            if ((cla & (~MASK_SECURED)) == ISO7816.CLA_ISO7816) {
                if (ins == ISO7816.INS_SELECT) {
                    processSelect();
                    return;
                }
            }

            switch (ins) {
            case INS_INITIALIZE_UPDATE:
            case ISO7816.INS_EXTERNAL_AUTHENTICATE:
            case INS_BEGIN_RMAC_SESSION:
            case INS_END_RMAC_SESSION:
                checkClaIsGp();
                // allow to make contactless SCP
                // checkProtocolContacted();
                processSecurity();
                break;
            default:
                processInternal(apdu);
            }

        } finally {
            if (apduData != null) {
                apduData = null;
                requestObjectDeletion();
            }
        }
    }

    public void deselect()
    {
        m_status[1] = (byte)(m_status[1] | 2);
        secureChannel.resetSecurity();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength)
    {
        new CafeBabeApplet().register(
            bArray, (short)(bOffset + 1), bArray[bOffset]);
    }

    public void uninstall()
    {
        apduData = null;
        m_status = null;
        m_control = null;
        m_memo = null;
    }

    public void processInternal(APDU apdu) throws ISOException
    {
        switch (this.ins) {
        case INS_HELLOWORLD:
            ins_helloworld();
            break;
        case INS_POKE:
            ins_poke();
            break;
        case INS_ECHO:
            ins_echo();
            break;
        case INS_CONTROL:
            ins_control();
            break;
        default:
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    public byte[] getApduData()
    {
        if (APDU.getCurrentAPDU().getCurrentState()
            < APDU.STATE_PARTIAL_INCOMING) {
            APDUException.throwIt(APDUException.ILLEGAL_USE);
        }
        if (apduData == null) {
            return APDU.getCurrentAPDUBuffer();
        } else {
            return apduData;
        }
    }

    public short setIncomingAndReceiveUnwrap()
    {
        byte[] buffer = APDU.getCurrentAPDUBuffer();
        short bytesRead = APDU.getCurrentAPDU().setIncomingAndReceive();
        short apduDataOffset = APDU.getCurrentAPDU().getOffsetCdata();
        boolean isExtendedLengthData
            = apduDataOffset == ISO7816.OFFSET_EXT_CDATA;
        short overallLength = APDU.getCurrentAPDU().getIncomingLength();

        if (isExtendedLengthData) {
            apduData = new byte[LENGTH_APDU_EXTENDED];

            Util.arrayCopyNonAtomic(buffer,
                                    (short)0,
                                    apduData,
                                    (short)0,
                                    (short)(apduDataOffset + bytesRead));

            if (bytesRead != overallLength) {
                short received = 0;
                do {
                    received = APDU.getCurrentAPDU().receiveBytes((short)0);
                    Util.arrayCopyNonAtomic(buffer,
                                            (short)0,
                                            apduData,
                                            (short)(apduDataOffset + bytesRead),
                                            received);
                    bytesRead += received;
                } while (!(received == 0 || bytesRead == overallLength));
            }

            buffer = apduData;
        }

        short result = overallLength;
        byte sl = secureChannel.getSecurityLevel();
        if ((sl & SecureChannel.C_DECRYPTION) != 0
            || (sl & SecureChannel.C_MAC) != 0) {
            result = (short)(secureChannel.unwrap(
                                 buffer,
                                 (short)0,
                                 (short)(apduDataOffset + overallLength))
                             - apduDataOffset);
        }
        Util.arrayCopyNonAtomic(
            buffer, apduDataOffset, buffer, (short)0, result);
        short bytesLeft = (short)(apduDataOffset - result);
        if (bytesLeft > 0) {
            Util.arrayFillNonAtomic(buffer,
                                    (short)(apduDataOffset - bytesLeft),
                                    bytesLeft,
                                    (byte)0);
        }

        return result;
    }

    protected void setOutgoingAndSendWrap(byte[] buffer, short bOff, short len)
    {
        if (APDU.getCurrentAPDU().getCurrentState() < APDU.STATE_OUTGOING) {
            APDU.getCurrentAPDU().setOutgoing();
        }

        byte sl = secureChannel.getSecurityLevel();

        if ((sl & SecureChannel.R_ENCRYPTION) != 0
            || (sl & SecureChannel.R_MAC) != 0) {
            len = secureChannel.wrap(buffer, bOff, len);
        }

        APDU.getCurrentAPDU().setOutgoingLength(len);
        APDU.getCurrentAPDU().sendBytesLong(buffer, bOff, len);
    }

    protected boolean isCheckC_MAC()
    {
        byte sl = secureChannel.getSecurityLevel();

        if ((cla & MASK_SECURED) > 0) {
            if (((sl & SecureChannel.AUTHENTICATED) == 0)
                || ((sl & SecureChannel.C_MAC) == 0)) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            return true;
        } else {
            if ((sl & SecureChannel.AUTHENTICATED) != 0) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            return false;
        }
    }

    protected boolean isCheckC_DECRYPTION()
    {
        byte sl = secureChannel.getSecurityLevel();

        if ((cla & MASK_SECURED) > 0) {
            if (((sl & SecureChannel.AUTHENTICATED) == 0)
                || ((sl & SecureChannel.C_DECRYPTION) == 0)) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            return true;
        } else {
            if ((sl & SecureChannel.AUTHENTICATED) != 0) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            return false;
        }
    }

    protected void checkClaIsInterindustry()
    {
        if ((cla & MASK_GP) != ISO7816.CLA_ISO7816) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
    }

    protected void checkProtocolContacted()
    {
        if (!isAPDUProtocolContacted()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    protected boolean isAPDUProtocolContacted()
    {
        return ((APDU.getProtocol() & APDU.PROTOCOL_MEDIA_MASK)
                == APDU.PROTOCOL_MEDIA_DEFAULT);
    }

    public void checkClaIsGp()
    {
        if ((cla & MASK_GP) != MASK_GP) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
    }

    protected void processSecurity()
    {
        // send to ISD
        short responseLength
            = secureChannel.processSecurity(APDU.getCurrentAPDU());
        if (responseLength != 0) {
            APDU.getCurrentAPDU().setOutgoingAndSend(
                (short)ISO7816.OFFSET_CDATA, responseLength);
        }
    }

    public SecureChannel getSecurityObject()
    {
        return secureChannel;
    }

    ////////////////////////////////////////////////////////////////////////////

    private void ins_helloworld()
    {
        if (p2 == 0x00) {
            setIncomingAndReceiveUnwrap();
            byte[] buffer = getApduData();
            short length = (short)helloWorld.length;
            Util.arrayCopyNonAtomic(
                helloWorld, (short)0, buffer, (short)0, length);
            setOutgoingAndSendWrap(buffer, SHORT_00, length);
        }
    }

    public void ins_poke()
    {
        byte sl = secureChannel.getSecurityLevel();
        m_status[0] = sl;

        if (p1 == 0x00) {
            setIncomingAndReceiveUnwrap();
            byte[] buffer = getApduData();

            Util.arrayCopyNonAtomic(
                m_status, (short)0, buffer, (short)0, STATUS_LEN);
            setOutgoingAndSendWrap(buffer, SHORT_00, STATUS_LEN);
        }
    }

    public void ins_echo()
    {
        if ((m_control[0] & 1) == 1) {
            if (!(isCheckC_MAC() && isCheckC_DECRYPTION())) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
        } else if ((m_control[0] & 2) == 2) {
            if (!(isCheckC_MAC() || isCheckC_DECRYPTION())) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
        }

        if (p1 == 0x00) {
            short lc = setIncomingAndReceiveUnwrap();
            byte[] buffer = getApduData();

            if (lc > 0) {
                if ((p2 & 1) != 0) {
                    if (m_memo != null) {
                        m_memo = null;
                        requestObjectDeletion();
                    }

                    m_memo = new byte[lc];
                    Util.arrayCopy(
                        buffer, (short)0, m_memo, (short)0, (short)lc);
                }

                if ((p2 & 2) == 0) {
                    setOutgoingAndSendWrap(buffer, SHORT_00, lc);
                }

            } else {
                if (m_memo != null) {
                    lc = (short)m_memo.length;
                    Util.arrayCopyNonAtomic(
                        m_memo, (short)0, buffer, (short)0, (short)lc);
                    setOutgoingAndSendWrap(buffer, SHORT_00, lc);
                }
            }
        }
    }

    public void ins_control()
    {
        m_control[p1] = p2;
    }
}
