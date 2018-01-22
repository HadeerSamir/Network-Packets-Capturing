
package wireshark;


public class Packet {
    
    
    int index;
    String data;
    String payload;
    
    
    Packet(int index,String data,String payload){
        this .index=index;
        this.data=data;
        this.payload=payload;
        
    }
    
}
