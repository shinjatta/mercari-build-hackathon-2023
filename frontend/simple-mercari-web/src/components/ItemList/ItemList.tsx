import React from "react";
import { Item } from "../Item";
interface Item {
  id: number;
  name: string;
  price: number;
  category_name: string;
}

interface Prop {
  items: Item[];
}

export const ItemList: React.FC<Prop> = (props) => {
  return (
    <div>
      <h2>List of items</h2>
      <div className="grid-container">
      {props.items &&
        props.items.map((item) => {
          return <Item item={item} />;
        })}
    </div>
    </div>
    
  );
};
