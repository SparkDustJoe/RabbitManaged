/*----------------------------------------------------------------------------*/
/* Rabbit C source code in ECRYPT format (Original Copyright Notice in Source)*/
/*----------------------------------------------------------------------------*/
/* Copyright (C) Cryptico A/S. All rights reserved.                           */
/*                                                                            */
/* YOU SHOULD CAREFULLY READ THIS LEGAL NOTICE BEFORE USING THIS SOFTWARE.    */
/*                                                                            */
/* This software is developed by Cryptico A/S and/or its suppliers.           */
/* All title and intellectual property rights in and to the software,         */
/* including but not limited to patent rights and copyrights, are owned by    */
/* Cryptico A/S and/or its suppliers.                                         */
/*                                                                            */
/* The software may be used solely for non-commercial purposes                */
/* without the prior written consent of Cryptico A/S. For further             */
/* information on licensing terms and conditions please contact Cryptico A/S  */
/* at [DEAD LINK] (NOTE: This was later amended to Public Domain, 2008)       */
/*                                                                            */
/* Cryptico, CryptiCore, the Cryptico logo and "Re-thinking encryption" are   */
/* either trademarks or registered trademarks of Cryptico A/S.                */
/*                                                                            */
/* Cryptico A/S shall not in any way be liable for any use of this software.  */
/* The software is provided "as is" without any express or implied warranty.  */
/*                                                                            */
/******************************************************************************/
// Modified September 2017, Dustin Sparks, Lexicon Informatics Consulting, LLC
// Ported to C# from original source
// http://www.ecrypt.eu.org/stream/e2-rabbit.html

using System;
using System.Runtime.CompilerServices;

namespace RabbitManaged
{
    public class Rabbit
    {
        #region CONSTANTS
        public const int BlockSize = 128;
        public const int KeySize = 128;
        public const int IVSize = 64;
        #endregion //CONSTANTS

        #region INTERNAL STRUCTURES
        internal class Context
        {
            public UInt32 Carry;
            public UInt32[] Counters;
            public UInt32[] State;

            public Context()
            {
                Carry = 0;
                Counters = new UInt32[8];
                State = new UInt32[8];
            }

            public Context Clone(bool IncludeCounters)
            {
                Context temp = new Context();
                temp.Carry = this.Carry;
                if (IncludeCounters)
                    Buffer.BlockCopy(this.Counters, 0, temp.Counters, 0, sizeof(UInt32) * this.Counters.Length);
                Buffer.BlockCopy(this.State, 0, temp.State, 0, sizeof(UInt32) * this.State.Length);
                return temp;
            }

            public void Clear()
            {
                Carry = 0;
                for (int i = 0; i < Counters.Length; i++)
                {   Counters[i] = State[i] = 0; }
            }
        }     
        private Context _master = new Context();
        private Context _working; // this is created on class construction/initialization
        #endregion //INTERNAL STRUCTURES

        #region PROPERTIES
        internal bool _INIT = false;
        public bool Initialized { get { return _INIT; } }
        #endregion // PROPERTIES

        #region INITIALIZERS / CONSTRUCTORS
        public Rabbit(byte[] key)
        {
            Initialize(key);
        }

        public Rabbit(byte[] key, byte[] iv)
        {
            Initialize(key, iv);
        }

        public void Initialize(byte[] key)
        {
            if (key != null && key.Length != 16)
                throw new ArgumentOutOfRangeException("key", "If Key is not NULL, then Key MUST be 16 bytes in length!");
            KeySetup(key);
            _INIT = true;
        }

        public void Initialize(byte[] key, byte[] iv)
        {
            if (key != null && key.Length != 16)
                throw new ArgumentOutOfRangeException("key", "If Key is not NULL, then Key MUST be 16 bytes in length!");
            KeySetup(key);
            _INIT = true;
            ReSeedIV(iv); // use the public method to validate the array
        }

        #endregion // INITIALIZERS / CONSTRUCTORS

        #region OTHER PUBLIC METHODS
        public void ReSeedIV(byte[] iv)
        {
            if (!Initialized)
                throw new InvalidOperationException("Cannot set IV if object not initialized! Call Initialize(x[,x]) first!");
            if (iv != null && iv.Length != 8)
                throw new ArgumentOutOfRangeException("iv", "If IV is not NULL, then IV MUST be 8 bytes in length!");
            if (iv == null)
            {
                _working = _master.Clone(true); // assume a blank reset to master 
                return;
            }
            IVSetup(iv);
        }

        public byte[] KeyStreamBytes(int length)
        {
            if (!Initialized)
                throw new InvalidOperationException("Cannot get KeyStream if object not initialized! Call Initialize(x[,x]) first!");
            if (length < 1)
                throw new ArgumentOutOfRangeException("length", "Length must be an integer greater than 1.");

            /* Temporary variables */
            UInt32[] buffer = new UInt32[4];
            byte[] output = new byte[length];
            int outputPointer = 0;
            
            /* Generate full blocks and fill output (partial block at the end as needed) */
            while (length > 0)
            {
                /* Iterate the system */
                NextState(_working);

                /* Generate 16 bytes of pseudo-random data */
                buffer[0] = (_working.State[0] ^ (_working.State[5] >> 16) ^ (UInt32)(_working.State[3] << 16));
                buffer[1] = (_working.State[2] ^ (_working.State[7] >> 16) ^ (UInt32)(_working.State[5] << 16));
                buffer[2] = (_working.State[4] ^ (_working.State[1] >> 16) ^ (UInt32)(_working.State[7] << 16));
                buffer[3] = (_working.State[6] ^ (_working.State[3] >> 16) ^ (UInt32)(_working.State[1] << 16));
                if (length >=16)    
                    Buffer.BlockCopy(buffer, 0, output, outputPointer, 16);
                else
                    Buffer.BlockCopy(buffer, 0, output, outputPointer, length);

                /* Increment output and Decrement length */
                outputPointer += 16;
                length -= 16;
            }

            return output;
        }

        public void Clear()
        {
            _INIT = false;
            if (_working != null)
                _working.Clear();
            if (_master != null)
                _master.Clear();
        }
        #endregion //PUBLIC METHODS

        #region CORE FUNCTIONS
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static UInt32 RotateLeft(UInt32 x, byte count)
        {
            return (x << count) | (x >> (32 - count));
        }

        /* G Function:  Square a 32-bit unsigned integer to obtain the 64-bit result and return */
        /* the upper 32 bits XOR the lower 32 bits */
        internal static UInt32 _G(UInt32 x)
        {
            /* Temporary variables */
            UInt32 a, b, h, l;

            /* Construct high and low argument for squaring */
            a = x & 0xFFFF;
            b = x >> 16;

            /* Calculate high and low result of squaring */
            h = ((((a * a) >> 17) + (a * b)) >> 15) + (b * b);
            l = (UInt32)(x * x);

            /* Return high XOR low */
            return h ^ l;
        }

        /* Calculate the next internal state */
        internal static void NextState(Context ctx)
        {
            /* Temporary variables */
            UInt32[] g = new UInt32[8];
            UInt32[] c_old = new UInt32[8];
            byte i;

            /* Save old counter values */
            for (i = 0; i < 8; i++)
                c_old[i] = ctx.Counters[i];

            /* Calculate new counter values */
            ctx.Counters[0] = (UInt32)(ctx.Counters[0] + 0x4D34D34D + ctx.Carry);
            ctx.Counters[1] = (UInt32)(ctx.Counters[1] + 0xD34D34D3 + (ctx.Counters[0] < c_old[0] ? 1 : 0));
            ctx.Counters[2] = (UInt32)(ctx.Counters[2] + 0x34D34D34 + (ctx.Counters[1] < c_old[1] ? 1 : 0));
            ctx.Counters[3] = (UInt32)(ctx.Counters[3] + 0x4D34D34D + (ctx.Counters[2] < c_old[2] ? 1 : 0));
            ctx.Counters[4] = (UInt32)(ctx.Counters[4] + 0xD34D34D3 + (ctx.Counters[3] < c_old[3] ? 1 : 0));
            ctx.Counters[5] = (UInt32)(ctx.Counters[5] + 0x34D34D34 + (ctx.Counters[4] < c_old[4] ? 1 : 0));
            ctx.Counters[6] = (UInt32)(ctx.Counters[6] + 0x4D34D34D + (ctx.Counters[5] < c_old[5] ? 1 : 0));
            ctx.Counters[7] = (UInt32)(ctx.Counters[7] + 0xD34D34D3 + (ctx.Counters[6] < c_old[6] ? 1 : 0));
            ctx.Carry = (UInt32)(ctx.Counters[7] < c_old[7] ? 1 : 0);

            /* Calculate the g-values */
            for (i = 0; i < 8; i++)
                g[i] = _G((UInt32)(ctx.State[i] + ctx.Counters[i]));

            /* Calculate new state values */
            ctx.State[0] = (UInt32)(g[0] + RotateLeft(g[7], 16) + RotateLeft(g[6], 16));
            ctx.State[1] = (UInt32)(g[1] + RotateLeft(g[0], 8) + g[7]);
            ctx.State[2] = (UInt32)(g[2] + RotateLeft(g[1], 16) + RotateLeft(g[0], 16));
            ctx.State[3] = (UInt32)(g[3] + RotateLeft(g[2], 8) + g[1]);
            ctx.State[4] = (UInt32)(g[4] + RotateLeft(g[3], 16) + RotateLeft(g[2], 16));
            ctx.State[5] = (UInt32)(g[5] + RotateLeft(g[4], 8) + g[3]);
            ctx.State[6] = (UInt32)(g[6] + RotateLeft(g[5], 16) + RotateLeft(g[4], 16));
            ctx.State[7] = (UInt32)(g[7] + RotateLeft(g[6], 8) + g[5]);
        }

        /* Key setup */
        internal void KeySetup(byte[] key)
        {
            /* Temporary variables */
            UInt32[] k = new UInt32[] { 0, 0, 0, 0 };
            byte i;

            /* Generate four subkeys */
            if (key != null)
                Buffer.BlockCopy(key, 0, k, 0, key.Length);

            /* Generate initial state variables */
            _master.State[0] = k[0];
            _master.State[2] = k[1];
            _master.State[4] = k[2];
            _master.State[6] = k[3];
            _master.State[1] = (UInt32)(k[3] << 16) | (k[2] >> 16);
            _master.State[3] = (UInt32)(k[0] << 16) | (k[3] >> 16);
            _master.State[5] = (UInt32)(k[1] << 16) | (k[0] >> 16);
            _master.State[7] = (UInt32)(k[2] << 16) | (k[1] >> 16);

            /* Generate initial counter values */
            _master.Counters[0] = RotateLeft(k[2], 16);
            _master.Counters[2] = RotateLeft(k[3], 16);
            _master.Counters[4] = RotateLeft(k[0], 16);
            _master.Counters[6] = RotateLeft(k[1], 16);
            _master.Counters[1] = (k[0] & 0xFFFF0000) | (k[1] & 0xFFFF);
            _master.Counters[3] = (k[1] & 0xFFFF0000) | (k[2] & 0xFFFF);
            _master.Counters[5] = (k[2] & 0xFFFF0000) | (k[3] & 0xFFFF);
            _master.Counters[7] = (k[3] & 0xFFFF0000) | (k[0] & 0xFFFF);

            /* Clear carry bit */
            _master.Carry = 0;

            /* Iterate the system four times */
            for (i = 0; i < 4; i++)
                NextState(_master);

            /* Modify the counters */
            for (i = 0; i < 8; i++)
                _master.Counters[i] ^= _master.State[(i + 4) & 0x7];

            /* Copy master instance to work instance */
            _working = _master.Clone(true); // include counters
        }

        /* IV setup */
        internal void IVSetup(byte[] iv)
        {
            if (iv == null) return;

            /* Temporary variables */
            UInt32[] ii = new UInt32[] { 0, 0, 0, 0 };
            UInt32 i;
                        
            /* Generate four subvectors */
            Buffer.BlockCopy(iv, 0, ii, 0, 4); //ii[0] = U8TO32_LITTLE(iv + 0);
            Buffer.BlockCopy(iv, 4, ii, 8, 4); //ii[2] = U8TO32_LITTLE(iv + 4);
            ii[1] = (ii[0] >> 16) | (ii[2] & 0xFFFF0000);
            ii[3] = (ii[2] << 16) | (ii[0] & 0x0000FFFF);

            /* Copy master instance to work instance */
            _working = _master.Clone(false); // don't include counters, they are set below

            /* Modify counter values */
            _working.Counters[0] = _master.Counters[0] ^ ii[0];
            _working.Counters[1] = _master.Counters[1] ^ ii[1];
            _working.Counters[2] = _master.Counters[2] ^ ii[2];
            _working.Counters[3] = _master.Counters[3] ^ ii[3];
            _working.Counters[4] = _master.Counters[4] ^ ii[0];
            _working.Counters[5] = _master.Counters[5] ^ ii[1];
            _working.Counters[6] = _master.Counters[6] ^ ii[2];
            _working.Counters[7] = _master.Counters[7] ^ ii[3];

            /* Iterate the system four times */
            for (i = 0; i < 4; i++)
                NextState(_working);
        }
        #endregion // CORE FUNCTIONS
    }
}
