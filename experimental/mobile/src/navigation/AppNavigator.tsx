import React from 'react';
import { NavigationContainer } from '@react-navigation/native';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import { createNativeStackNavigator } from '@react-navigation/native-stack';
import { Text, View, StyleSheet } from 'react-native';
import { RootTabParamList, RootStackParamList } from '../types';
import { useAuth } from '../hooks/useAuth';
import { colors, fontSize } from '../styles/tokens';

// Screens
import FeedScreen from '../screens/FeedScreen';
import UploadScreen from '../screens/UploadScreen';
import ProfileScreen from '../screens/ProfileScreen';
import LoginScreen from '../screens/LoginScreen';

const Tab = createBottomTabNavigator<RootTabParamList>();
const Stack = createNativeStackNavigator<RootStackParamList>();

const TAB_ICONS: Record<string, string> = {
  Feed:    '⊞',
  Upload:  '⊕',
  Profile: '◎',
};

function TabIcon({ name, focused }: { name: string; focused: boolean }) {
  return (
    <View style={styles.tabIconWrap}>
      {focused && <View style={styles.tabActiveBar} />}
      <Text style={[styles.tabIcon, focused && styles.tabIconActive]}>
        {TAB_ICONS[name] ?? '·'}
      </Text>
    </View>
  );
}

function MainTabs() {
  return (
    <Tab.Navigator
      screenOptions={({ route }) => ({
        tabBarIcon: ({ focused }) => <TabIcon name={route.name} focused={focused} />,
        tabBarLabel: ({ focused, children }) => (
          <Text style={[styles.tabLabel, focused && styles.tabLabelActive]}>
            {children}
          </Text>
        ),
        tabBarStyle: styles.tabBar,
        headerShown: false,
      })}
    >
      <Tab.Screen name="Feed"    component={FeedScreen} />
      <Tab.Screen name="Upload"  component={UploadScreen} />
      <Tab.Screen name="Profile" component={ProfileScreen} />
    </Tab.Navigator>
  );
}

export default function AppNavigator() {
  const { user, loading } = useAuth();

  if (loading) return null;

  return (
    <NavigationContainer>
      <Stack.Navigator screenOptions={{ headerShown: false }}>
        {user ? (
          <Stack.Screen name="Main" component={MainTabs} />
        ) : (
          <>
            <Stack.Screen name="Login"    component={LoginScreen} />
            <Stack.Screen name="Register" component={LoginScreen} />
          </>
        )}
      </Stack.Navigator>
    </NavigationContainer>
  );
}

const styles = StyleSheet.create({
  tabBar: {
    backgroundColor: colors.surface,
    borderTopColor:  colors.border,
    borderTopWidth:  1,
    height:          64,
    paddingBottom:   8,
    paddingTop:      4,
  },
  tabIconWrap: {
    alignItems: 'center',
    position:   'relative',
    width:      36,
  },
  tabActiveBar: {
    position:    'absolute',
    top:         -4,
    left:        4,
    right:       4,
    height:      3,
    borderRadius: 2,
    backgroundColor: colors.primary,
  },
  tabIcon: {
    fontSize:   20,
    color:      colors.muted,
    lineHeight: 24,
  },
  tabIconActive: {
    color: colors.primary,
  },
  tabLabel: {
    fontSize:   11,
    color:      colors.muted,
    fontWeight: '500',
    marginTop:  2,
  },
  tabLabelActive: {
    color:      colors.primary,
    fontWeight: '700',
  },
});
