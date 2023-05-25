import { useCookies } from "react-cookie";
import { useNavigate } from "react-router-dom";
import "./Header.css";
import logo from '../../logo.png';
import { useState } from "react";

export const Header: React.FC = () => {
  const [cookies, _, removeCookie] = useCookies(["userID", "token"]);
  const navigate = useNavigate();
  const [searchValue, setSearchValue] = useState("");

  const onLogout = (event: React.MouseEvent<HTMLButtonElement, MouseEvent>) => {
    event.preventDefault();
    removeCookie("userID");
    removeCookie("token");
  };

  const handleSearch = () => {
    navigate(`/items/search/${searchValue}`);
  };

  return (
    <>
      <header>
        <div className="LogoContainer" onClick={() => navigate("/")}>
          <img className="logo" src={logo} alt="Logo" />
        </div>
        <div className="searchContainer">
          <input
            type="text"
            id="MerTextInput"
            className="SearchBar"
            placeholder="What are you looking for?"
            value={searchValue}
            onChange={(e) => setSearchValue(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                handleSearch();
              }
            }}
          />
          <div onClick={handleSearch} id="SearchButton">
         
          </div>
          <button onClick={handleSearch} id="SearchButton">
            Search
          </button>
        </div>
        <div className="navContainer">
          <span className="navButton" onClick={() => navigate("/")}>Home</span>
          <span className="navButton" onClick={() => navigate("/sell")}>Listing</span>
          <span className="navButton" onClick={() => navigate(`/user/${cookies.userID}`)}>MyPage</span>
        </div>
        <div className="LogoutButtonContainer">
          <button onClick={onLogout} id="MerButton">
            Logout
          </button>
        </div>
      </header>
    </>
  );
}
