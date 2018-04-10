package edu.jduan8.pcaparser;


interface IPacket {
    byte[] field(String field);
    String type();
    IPacket next();     /* previous layer */

//    @SuppressWarnings("unchecked")
//    byte[] field(String field, Class<T> cls) {
//        HashMap<String, Integer> map = null;
//        int[] ofst = {};
//        int[] len = {};
//
//        try {
//            Field map_field = cls.getDeclaredField("map");
//            Field ofst_field = cls.getDeclaredField("offset");
//            Field len_field = cls.getDeclaredField("length");
//            map = (HashMap)map_field.get(cls);
//            ofst = (int[])ofst_field.get(cls);
//            len = (int[])len_field.get(cls);
//        } catch(Exception e) {
//            e.printStackTrace();
//        }
//        assert map != null;
//        if(!map.containsKey(field)) return null;
//        int i = map.get(field);
//
//        assert i >= 0 && i < ofst.length;
//
//        return Arrays.copyOfRange(buffer, ofst[i], ofst[i]+len[i]);
//    }
}
