import { Login } from "../Login";
import { Signup } from "../Signup";
import { useParams, useNavigate } from "react-router-dom";
import { ItemList } from "../ItemList";
import { useCookies } from "react-cookie";
import { MerComponent } from "../MerComponent";
import { useEffect, useState } from "react";
import { toast } from "react-toastify";
import { fetcher } from "../../helper";
import "react-toastify/dist/ReactToastify.css";

interface Item {
  id: number;
  name: string;
  price: number;
  category_name: string;
}
export const Search = () => {
  const [cookies] = useCookies(["userID", "token"]);
  const [items, setItems] = useState<Item[]>([]);
  const params = useParams();

  const fetchItems = () => {
    fetcher<Item[]>(`/items/search/${params.search}`, {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
    })
      .then((data) => {
        console.log("GET success:", data);
        setItems(data);
      })
      .catch((err) => {
        console.log(`GET error:`, err);
        toast.error(err.message);
      });
  };

  useEffect(() => {
    fetchItems();
  }, []);

  const signUpAndSignInPage = (
    <>
      <div>
        <Signup />
      </div>
      or
      <div>
        <Login />
      </div>
    </>
  );

  const itemListPage = (
    <MerComponent>
      <div>
        <span>
          <p>Logined User ID: {cookies.userID}</p>
        </span>
        <ItemList items={items} />
      </div>
    </MerComponent>
  );

  return <>{cookies.token ? itemListPage : signUpAndSignInPage}</>;
};
