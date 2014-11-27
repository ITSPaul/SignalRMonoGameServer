using Microsoft.Xna.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace SignalRServer
{
    public enum COLLECTABLE_TYPE { STANDARD, MEDIUM, COMPLEX}

    public class Player
    {
        int _playerID;

        public int PlayerID
        {
            get { return _playerID; }
            set { _playerID = value; }
        }
        Vector2 _position;

        public Vector2 Position
        {
            get { return _position; }
            set { _position = value; }
        }

        int _score;

        public int Score
        {
            get { return _score; }
            set { _score = value; }
        }

        public bool _firstIn;

        public Player(int id, Vector2 pos)
        {
            _playerID = id;
            _position = pos;
        }
    }

    public enum GAMESTATE { NONE, STARTING, PLAYING, ENDING, FINISHED }

    public class Collectable
    {
        int _id;
        COLLECTABLE_TYPE _type;

        public COLLECTABLE_TYPE Type
        {
            get { return _type; }
            set { _type = value; }
        }
        public int Id
        {
            get { return _id; }
            set { _id = value; }
        }
        int _value;
        bool _collected;

        public bool Collected
        {
            get { return _collected; }
            set { _collected = value; }
        }
        public int Value
        {
            get { return _value; }
            set { _value = value; }
        }
        Vector2 _position;
        public Vector2 Position
        {
            get { return _position; }
            set { _position = value; }
        }
        
        // colleectale value should be 10, 20 or 30
        public Collectable(int id, Vector2 pos, int value)
        {
            _id = id;
            _position = pos;
            _value = value;
            _collected = false;
            switch (value)
            {
                case 10:
                    _type = COLLECTABLE_TYPE.STANDARD;
                    break;
                case 20:
                    _type = COLLECTABLE_TYPE.MEDIUM;
                    break;
                case 30:
                    _type = COLLECTABLE_TYPE.COMPLEX;
                    break;
            }
        }
    }
}