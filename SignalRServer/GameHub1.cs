using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using Microsoft.AspNet.SignalR;
using Microsoft.AspNet.SignalR.Hubs;
using Microsoft.Xna.Framework;
using System.Timers;
using System.Threading.Tasks;
using Utilities;
using SignalRServer.Models;

namespace SignalRServer
{
    [HubName("GameHub")]
    public class GameHub : Hub
    {
        
        public static GAMESTATE state = GAMESTATE.NONE;
        public static int _playerCounter = 0;
        public static int _playersPlaying = 0;
        public static Dictionary<int, Player> _players = new Dictionary<int, Player>();
        public static Dictionary<int, Collectable> _collectables = new Dictionary<int, Collectable>();
        public static Timer _startTime;
        public static bool _gameStarted = false;
        public static bool _gameOver = false;
        public static Vector2 worldEnd = new Vector2(800, 600);

        public Vector2 WorldsEnd()
        {
            return worldEnd;
        }

        public bool login(string username, string password)
        {
            return true;
        }


        public Player joinServer()
        {
            Player NewPlayer = null;
            switch (state) { 
                case GAMESTATE.NONE:
                    NewPlayer = setupPlayer();
                    if (_playersPlaying > 1)
                            {
                                state = GAMESTATE.STARTING;
                                _startTime = new Timer(10000);
                                _startTime.Elapsed += _startTime_Elapsed;
                                _startTime.Start();
                                Clients.All.TimerOn(_startTime.Interval);
                            }
                    break;
                case GAMESTATE.STARTING:
                    NewPlayer = setupPlayer();
                    break;
                }
            return NewPlayer;
        }

        public Player setupPlayer()
        {
                        //_playerCounter++;
            int count = _players.Count;
            // Player initial position has to be set on the server as this will be needed in 
            // others
            Player p = new Player(count, randomPosition((int)worldEnd.X - 50, (int)worldEnd.Y - 50));
            _players.Add(p.PlayerID,p);
            // Inform the Caller that the player has joined the game
            //Clients.Caller.JoinedServer(_players[count]);
            // Inform other clients that this player has joined
            Clients.Others.AddOtherPlayer(p);
            //Player other;
            //for (int i = 0; i < _players.Count - 1; i++)
            //{
            //    other = _players[i];
            //    // Inform the caller of all the other players who have joined
            //    Clients.Caller.AddOtherPlayer(other);
            //}
            _playersPlaying++;
            return p;
        }

        public List<KeyValuePair<int,Player>> getOthers(int CurrentPlayerExcluded)
        {
            var others = _players.Where(p => p.Value.PlayerID != CurrentPlayerExcluded).ToList(); ;
            return others;
        }

        void _startTime_Elapsed(object sender, ElapsedEventArgs e)
        {
            switch (state) { 
                case GAMESTATE.STARTING:
                    _startTime.Stop();
                    Clients.All.Accept(createCollectables());
                    Clients.All.StartGame();
                    state = GAMESTATE.PLAYING;
                    break;
                // timer is activated for the top players to be displayed
                case GAMESTATE.ENDING:
                    _startTime.Stop();
                    state = GAMESTATE.FINISHED;
                    gameReset();
                    break;
            }


        }

        private Dictionary<int,Collectable> createCollectables()
        {
            Random r = new Random();
            int collectableCount = r.Next(3, 10);
            int[] possibles = { 10, 20, 30 };
            if(_collectables.Count == 0)
                for (int i = 0; i < collectableCount; i++)
                    // Add a collectable to the collection with a random position and a random possible value
                    _collectables.Add(i,
                        new Collectable(i, randomPosition((int)worldEnd.X - 40,(int)worldEnd.Y - 40),
                            possibles[Utility.NextRandom(0,2)]
                        ));
            return _collectables;
        }

        public void Collected(Player p, Collectable c)
        {
            switch (state) 
            { 
                case GAMESTATE.PLAYING:
                _players[p.PlayerID].Score += c.Value;
                _collectables[c.Id].Collected = true;
                Clients.Others.Gone(c);
                // if all collected then report the final score
                var collected = _collectables.Where(col => col.Value.Collected == false);
                if (collected.Count() == 0)
                {
                    var scoreBoard = _players.OrderByDescending(pl => pl.Value.Score).ToList();
                    Clients.All.PresentScoreBoard(scoreBoard);
                    state = GAMESTATE.ENDING;
                    gameReset();
                }
                break;
            }      
        }

        private void gameReset()
        {
            switch(state) {
                case GAMESTATE.ENDING:
                    _startTime.Start();
                    break;
                case GAMESTATE.FINISHED:
                     _playerCounter = 0;
                    _playersPlaying = 0;
                    _collectables = new Dictionary<int, Collectable>();
                    _players = new Dictionary<int, Player>();
                    // Allow others to join a new game
                    Clients.All.quitGame();
                    state = GAMESTATE.NONE;
                    break;
            }
                     
        }

        // depreciated by dictionary
        public void NewPlayer(Player p)
        {
            if(_playersPlaying > 0)
                Clients.Others.AddPlayer(p);
        }

        public void DeletePlayer(Player p)
        {
            if (_players.Count > 0)
            {
                Clients.Others.DeleteClientPlayerFromOthers(p);
               _players.Remove(p.PlayerID);
               _playersPlaying--;
            }
            else // reset the game
            {
                gameReset();
            }
        }

        public GAMESTATE getCurrentGameState()
        {
            return state;
        }

        public  Player getPlayer(int Id)
        {
            return _players[Id];
        }

        public int ActiveCollectableCount()
        {
            return _collectables.Where(p => p.Value.Collected == false).Count();
        }

        public void movePlayer(Player p)
        {
                _players[p.PlayerID].Position = p.Position;
                Clients.Others.UpdateOtherPlayerPosition(p);
        }

        public Vector2 randomPosition(int MaxX, int MaxY)
        {
            return new Vector2(Utility.NextRandom( 40,MaxX),
                                Utility.NextRandom(40,MaxY));
        }

    }
}